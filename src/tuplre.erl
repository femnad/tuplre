-module(tuplre).
-compile(export_all).
-define(CREDENTIALS_FILE, "~/.tuplrerc").
-define(FORM_CONTENT_TYPE, "application/x-www-form-urlencoded").

%% Application callbacks
-export([main/1]).

%%====================================================================
%% API
%%====================================================================
main(_Args) ->
    case get_credentials(?CREDENTIALS_FILE) of
        {Server, Email, Key} ->
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
            [Server, Email, Key] = lists:map(fun(X) -> proplists:get_value(X, Credential) end, [server, email, key]),
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
    case EndpointType of
        queue ->
            lists:flatten(io_lib:format("~s/api/v1/register", [ZulipServer]));
        _ ->
            lists:flatten(io_lib:format("~s/api/v1/~s",
                                        [ZulipServer, atom_to_list(EndpointType)]))
    end.

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
perform_request(URL, Headers, ContentType, Body) ->
    start_request(),
    {ok, Response} = httpc:request(post, {URL, Headers, ContentType, Body}, [], []),
    {_, _, ResponseBody} = Response,
    ResponseBody.

authorized_get_request(URL, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, [AuthorizationHeader]).
authorized_post_request(URL, ContentType, Body, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, [AuthorizationHeader], ContentType, Body).

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
    [SenderShortName, StreamName, Subject, Content] = lists:map(fun(X) -> get_key(Message, X) end,
                                                    [<<"sender_short_name">>,
                                                     <<"display_recipient">>,
                                                     <<"subject">>,
                                                     <<"content">>]),
    {SenderShortName, StreamName, Subject, Content}.

get_stream_name([Stream|Rest], StreamId) ->
    StreamDict = dict:from_list(Stream),
    {ok, Id} = dict:find(<<"stream_id">>, StreamDict),
    case Id == StreamId of
        true ->
            {ok, StreamName} = dict:find(<<"name">>, StreamDict),
            binary_to_list(StreamName);
        false ->
            get_stream_name(Rest, StreamId)
    end;
get_stream_name([], _) ->
    notfound.

format_message(Sender, Stream, Subject, Content) ->
    lists:flatten(io_lib:format("~s > ~s [~s]: ~s",
                                [Sender, Stream, Subject, Content])).

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
            {QueueId, LastEventId} = register_message_queue(ZulipServer, Username, Password),
            check_for_messages(ZulipServer, Username, Password, QueueId, LastEventId);
        _ ->
            Events = get_key(Json, <<"events">>),
            lists:map(fun get_message_with_id/1, Events)
    end.

consume_messages([{MessageID, Message} | Rest], _) ->
    {Sender, StreamName, Subject, Content} = get_message(Message),
    io:format("~s~n", [format_message(Sender, StreamName, Subject, Content)]),
    consume_messages(Rest, MessageID);
consume_messages([], MessageID) ->
    MessageID.

message_loop(ZulipServer, Username, Password, QueueID, LastEventID) ->
    receive
        _ ->
            ok
    after 1000 ->
            MessagesWithIds = check_for_messages(ZulipServer, Username, Password, QueueID, LastEventID),
            LastMessageId = consume_messages(MessagesWithIds, LastEventID),
            message_loop(ZulipServer, Username, Password, QueueID, LastMessageId)
    end.

get_streams(ZulipServer, Username, Password) ->
    StreamsEndpoint = get_endpoint(ZulipServer, streams),
    StreamsString = authorized_get_request(StreamsEndpoint, Username, Password),
    StreamsJson = jsx:decode(list_to_binary(StreamsString)),
    get_key(StreamsJson, <<"streams">>).
