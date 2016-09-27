-module(tuplre).
-define(CREDENTIALS_FILE, "~/.tuplrerc").
-define(FORM_CONTENT_TYPE, "application/x-www-form-urlencoded").

%% Application callbacks
-export([main/1, send_private_message/5, send_stream_message/6,
         subscribe_to_streams/4, get_streams/3, get_subscriptions/3,
         display_messages/0, print_message/1, remove_subscriptions/4]).

%%====================================================================
%% API
%%====================================================================
colorize(String, Color) ->
    EscapeCode = case Color of
                     red ->
                         31;
                     green ->
                         32;
                     yellow ->
                         33;
                     blue ->
                         34;
                     magenta ->
                         35;
                     cyan ->
                         36;
                     white ->
                         37;
                     _ ->
                         30
                 end,
    io_lib:format("\033[0;~Bm~s\033[0;0m", [EscapeCode, String]).

main(_Args) ->
    case get_credentials(?CREDENTIALS_FILE) of
        {Server, Email, Key} ->
            DisplayerPid = spawn(?MODULE, display_messages, []),
            register(displayer, DisplayerPid),
            message_loop(Server, Email, Key);
        file_not_found ->
            io:format("Unable to find credentials file in path ~s~n",
                      [?CREDENTIALS_FILE])
    end,
    erlang:halt(0).

get_credentials(File) ->
    CredentialsFile = expand_user(File),
    case file:consult(CredentialsFile) of
        {ok, Credentials} ->
            [Credential | _] = Credentials,
            [Server, Email, Key] = lists:map(
                                     fun(X) ->
                                             proplists:get_value(X, Credential)
                                     end, [server, email, key]),
            {Server, Email, Key};
        {error, enoent} ->
            file_not_found
    end.

message_loop(ZulipServer, Username, Password) ->
    {QueueID, LastEventID} = register_message_queue(ZulipServer, Username, Password),
    message_loop(ZulipServer, Username, Password, QueueID, LastEventID).

send_private_message(ZulipServer, Username, Password, Recipient, Message) ->
    send_message(ZulipServer, Username, Password, {Recipient, Message}).

send_stream_message(ZulipServer, Username, Password, Stream, Subject, Message) ->
    send_message(ZulipServer, Username, Password, {Stream, Subject, Message}).

%%====================================================================
%% Internal functions
%%====================================================================
expand_user(Path) ->
    UserHome = os:getenv("HOME"),
    re:replace(Path, "^~", UserHome, [{return, list}]).

get_endpoint(ZulipServer, EndpointType) ->
    ApiPrefix = "/api/v1/",
    EndpointSuffix = case EndpointType of
                         queue ->
                             "register";
                         subscription ->
                             "users/me/subscriptions";
                         _ ->
                             atom_to_list(EndpointType)
                     end,
    lists:flatten(io_lib:format("~s~s~s", [ZulipServer, ApiPrefix, EndpointSuffix])).

get_messages_endpoint(ZulipServer) ->
    get_endpoint(ZulipServer, messages).

get_queue_endpoint(ZulipServer) ->
    get_endpoint(ZulipServer, queue).

get_events_endpoint(ZulipServer) ->
    get_endpoint(ZulipServer, events).

get_format_string(T) ->
    case is_integer(T) of
        true ->
            "~w";
        false ->
            "~s"
    end.

format_key_value(K, V) ->
    FormatString = "~s=" ++ get_format_string(V),
    io_lib:format(FormatString, [K, V]).

delimit_key_value_pairs([KeyValuePair|Rest]) ->
    {Key, Value} = KeyValuePair,
    delimit_key_value_pairs(Rest, format_key_value(Key, Value)).

delimit_key_value_pairs([KeyValuePair|Rest], Acc) ->
    {Key, Value} = KeyValuePair,
    delimit_key_value_pairs(Rest, Acc ++ "&" ++ format_key_value(Key, Value));
delimit_key_value_pairs([], Acc) ->
    lists:flatten(Acc).

get_request_body(MessageComponents) ->
    case MessageComponents of
        {Stream, Subject, Message} ->
            delimit_key_value_pairs([{"content", Message},
                                     {"subject", Subject},
                                     {"to", Stream},
                                     {"type", "stream"}]);
        {Recipient, Message} ->
            delimit_key_value_pairs([{"content", Message},
                                     {"to", Recipient},
                                     {"type", "private"}])
    end.

send_message(ZulipServer, Username, Password, MessageComponents) ->
    RequestBody = get_request_body(MessageComponents),
    MessagesEndpoint = get_messages_endpoint(ZulipServer),
    authorized_post_request(MessagesEndpoint, ?FORM_CONTENT_TYPE, RequestBody,
                            Username, Password).

%%====================================================================
%% httpc API
%%====================================================================

get_basic_authorization_header(Username, Password) ->
    UsernameAndPassword = lists:flatten(io_lib:format("~s:~s", [Username, Password])),
    Base64Encoded = base64:encode_to_string(UsernameAndPassword),
    {"Authorization", lists:flatten(io_lib:format("Basic ~s", [Base64Encoded]))}.

start_request() ->
    inets:start(),
    ssl:start().

perform_request(URL, Headers) ->
    start_request(),
    {ok, Response} = httpc:request(get, {URL, Headers}, [], []),
    {_, _, ResponseBody} = Response,
    ResponseBody.
perform_request(URL, Headers, ContentType, Body, Method) ->
    start_request(),
    {ok, Response} = httpc:request(Method, {URL, Headers, ContentType, Body}, [], []),
    {_, _, ResponseBody} = Response,
    ResponseBody.
perform_request(URL, Headers, ContentType, Body) ->
    perform_request(URL, Headers, ContentType, Body, post).

authorized_get_request(URL, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, [AuthorizationHeader]).
authorized_post_request(URL, ContentType, Body, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, [AuthorizationHeader], ContentType, Body).
authorized_post_request(URL, Body, Username, Password) ->
    authorized_post_request(URL, ?FORM_CONTENT_TYPE, Body, Username, Password).
authorized_patch_request(URL, Body, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, [AuthorizationHeader], ?FORM_CONTENT_TYPE, Body, patch).

%%====================================================================
%% End of httpc API
%%====================================================================

register_message_queue(ZulipServer, Username, Password) ->
    RequestBody = lists:flatten("event_types=[\"message\"]"),
    QueueEndpoint = get_queue_endpoint(ZulipServer),
    Response = authorized_post_request(QueueEndpoint, ?FORM_CONTENT_TYPE,
                                             RequestBody, Username, Password),
    JsonString = list_to_binary(Response),
    RegisterResponse = jsx:decode(JsonString),
    [QueueId, LastEventId] = lists:map(fun(X) -> get_key(RegisterResponse, X) end,
                                       [<<"queue_id">>, <<"last_event_id">>]),
    {QueueId, LastEventId}.

get_key(KeyValueMap, Key) ->
    Filtered = [V || {K, V} <- KeyValueMap,
                     K == Key],
    case length(Filtered) of
        1 ->
            hd(Filtered);
        _ ->
            Filtered
    end.

get_message_with_id(Event) ->
    [ID, Message] = lists:map(fun(X) -> get_key(Event, X) end, [<<"id">>, <<"message">>]),
    {ID, Message}.

get_message(Message) ->
    [Sender, StreamName, Subject, Content] = lists:map(
                                                        fun(X) -> get_key(Message, X) end,
                                                        [<<"sender_full_name">>,
                                                         <<"display_recipient">>,
                                                         <<"subject">>,
                                                         <<"content">>]),
    {Sender, StreamName, Subject, Content}.

get_format_list(Omissions, MessageComponents, Acc) ->
    case Omissions of
        [] ->
            lists:reverse([hd(MessageComponents)|Acc]);
        _ ->
            [Component|RestComponents] = MessageComponents,
            [ComponentOmission|RestOmissions] = Omissions,
            NewAcc = case ComponentOmission of
                         true ->
                             Acc;
                         false ->
                             [Component|Acc]
                     end,
            get_format_list(RestOmissions, RestComponents, NewAcc)
    end.
get_format_list(Omissions, MessageComponents) ->
    get_format_list(Omissions, MessageComponents, []).

get_message_format_string(Omissions, Acc) ->
    case Omissions of
        [] ->
            Acc ++ "~s~n";
        _ ->
            [OmitCurrent|OmitRest] = Omissions,
            NewAcc = case OmitCurrent of
                         true ->
                             Acc;
                         false ->
                             Acc ++ "~s~n"
                     end,
            get_message_format_string(OmitRest, NewAcc)
    end.
get_message_format_string(Omissions) ->
    get_message_format_string(Omissions, "").

format_message(Sender, Stream, Subject, Content) ->
    format_message(Sender, Stream, Subject, Content, [false, false, false]).
format_message(Sender, Stream, Subject, Content, Omissions) ->
    FormatList = get_format_list(Omissions, [colorize(Sender, blue),
                                             colorize(Stream, yellow),
                                             colorize(Subject, green),
                                             Content]),
    FormatSpecifier = get_message_format_string(Omissions),
    lists:flatten(io_lib:format(FormatSpecifier, FormatList)).

check_for_messages(ZulipServer, Username, Password, QueueID, LastEventID) ->
    QueryString = delimit_key_value_pairs([{"queue_id", QueueID},
                                           {"last_event_id", LastEventID},
                                           {"dont_block", "true"}]),
    EventsEndpoint = lists:flatten(io_lib:format("~s?~s",
                                                 [get_events_endpoint(
                                                    ZulipServer), QueryString])),
    Response = authorized_get_request(EventsEndpoint, Username, Password),
    Json = jsx:decode(list_to_binary(Response)),
    case get_key(Json, <<"result">>) of
        <<"error">> ->
            %% Bad event queue id
            erlang:error("Invalid queue ID");
        _ ->
            Events = get_key(Json, <<"events">>),
            lists:map(fun get_message_with_id/1, Events)
    end.

determine_omissions(Sender, Stream, Subject,
                    NextSender, NextStream, NextSubject) ->
    [Sender == NextSender, Stream == NextStream, Subject == NextSubject].

replace_tildes(String) ->
    re:replace(String, "~", "~~", [{return,list}]).

print_message(Message) ->
    print_message(Message, none_before).
print_message(Message, PrevMessage) ->
    {Sender, Stream, Subject, Content} = get_message(Message),
    Formatted_Message = case PrevMessage of
                            none_before ->
                                format_message(Sender, Stream, Subject, Content);
                            _ ->
                                {PrevSender, PrevStream, PrevSubject, _} = get_message(
                                                                             PrevMessage),
                                Omissions = determine_omissions(Sender, Stream, Subject, PrevSender,
                                                                PrevStream, PrevSubject),
                                format_message(Sender, Stream, Subject, Content, Omissions)
                        end,
    io:format(replace_tildes(Formatted_Message)).

consume_messages([{MessageID, Message} | Rest], _) ->
    displayer ! Message,
    consume_messages(Rest, MessageID);
consume_messages([], MessageID) ->
    MessageID.

message_loop(ZulipServer, Username, Password, QueueID, LastEventID) ->
    receive
        _ ->
            ok
    after 1000 ->
            try check_for_messages(ZulipServer, Username, Password, QueueID,
                                   LastEventID) of
                MessagesWithIds ->
                    LastMessageId = consume_messages(MessagesWithIds,
                                                     LastEventID),
                    message_loop(ZulipServer, Username, Password, QueueID,
                                 LastMessageId)
            catch
                error:_Error ->
                    message_loop(ZulipServer, Username, Password)
            end
    end.

get_streams(ZulipServer, Username, Password) ->
    StreamsEndpoint = get_endpoint(ZulipServer, streams),
    StreamsString = authorized_get_request(StreamsEndpoint, Username, Password),
    StreamsJson = jsx:decode(list_to_binary(StreamsString)),
    get_key(StreamsJson, <<"streams">>).

get_subscription_body([StreamName|StreamNames]) ->
    get_subscription_body(StreamNames, [[{<<"name">>, list_to_binary(StreamName)}]]).
get_subscription_body([StreamName|StreamNames], Acc) ->
    get_subscription_body(StreamNames, [[{<<"name">>, list_to_binary(StreamName)}]|Acc]);
get_subscription_body([], Acc) ->
    jsx:encode(Acc).

get_subscriptions(ZulipServer, Username, Password) ->
    SubscriptionsEndpoint = get_endpoint(ZulipServer, subscription),
    Response = authorized_get_request(SubscriptionsEndpoint, Username, Password),
    JsonResponse = jsx:decode(list_to_binary(Response)),
    Subscriptions = get_key(JsonResponse, <<"subscriptions">>),
    [get_key(X, <<"name">>) || X <- Subscriptions].

subscribe_to_streams(ZulipServer, Username, Password, StreamNames) ->
    SubscriptionsEndpoint = get_endpoint(ZulipServer, subscription),
    RequestBody = lists:flatten(
                    io_lib:format(
                      "subscriptions=~s", [get_subscription_body(StreamNames)])),
    authorized_post_request(SubscriptionsEndpoint, RequestBody, Username, Password).

display_messages() ->
    display_messages(none_before).
display_messages(PreviousMessage) ->
    receive
        Message ->
            print_message(Message, PreviousMessage),
            notify_message(Message),
            display_messages(Message)
    end.

get_delete_subscriptions_body([Stream|Streams]) ->
    get_delete_subscriptions_body(Streams, "delete=[\"" ++ Stream ++ "\"").
get_delete_subscriptions_body([Stream|Streams], Acc) ->
    get_delete_subscriptions_body(Streams, Acc ++ ",\"" ++ Stream ++ "\"");
get_delete_subscriptions_body([], Acc) ->
    Acc ++ "]".

remove_subscriptions(ZulipServer, Username, Password, StreamNames) ->
    SubscriptionsEndpoint = get_endpoint(ZulipServer, subscription),
    DeleteSubscriptionsBody = get_delete_subscriptions_body(StreamNames),
    authorized_patch_request(SubscriptionsEndpoint, DeleteSubscriptionsBody,
                             Username, Password).

notify_message(Message) ->
    {Sender, Stream, Subject, Content} = get_message(Message),
    Header =io_lib:format("~s > ~s [~s]",
                          lists:map(
                            fun replace_tildes/1, [Sender, Stream, Subject])),
    Body = replace_tildes(Content),
    NotifySendCmd = lists:flatten(io_lib:format("notify-send '~s' '~s'", [Header, Body])),
    os:cmd(NotifySendCmd).
