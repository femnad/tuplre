%%%-------------------------------------------------------------------
%% @doc tuplre public API
%% @end
%%%-------------------------------------------------------------------

-module(tuplre_app).

-behaviour(application).

-define(FORM_CONTENT_TYPE, "application/x-www-form-urlencoded").
-define(JSON_CONTENT_TYPE, "application/json").

%% Application callbacks
-export([start/2, stop/1, send_private_message/5, send_stream_message/6, message_loop/3]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    tuplre_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
get_endpoint(ZulipServer, EndpointType) ->
    case EndpointType of
        messages ->
            lists:flatten(io_lib:format("~s/api/v1/messages", [ZulipServer]));
        queue ->
            lists:flatten(io_lib:format("~s/api/v1/register", [ZulipServer]));
        events ->
            lists:flatten(io_lib:format("~s/api/v1/events", [ZulipServer]))
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

%% httpc API

get_basic_authorization_header(Username, Password) ->
    UsernameAndPassword = lists:flatten(io_lib:format("~s:~s", [Username, Password])),
    Base64Encoded = base64:encode_to_string(UsernameAndPassword),
    {"Authorization", lists:flatten(io_lib:format("Basic ~s", [Base64Encoded]))}.

start_request() ->
    inets:start(),
    ssl:start().

perform_request(URL, Headers) ->
    start_request(),
    httpc:request(get, {URL, Headers}, [], []).
perform_request(URL, Headers, ContentType, Body) ->
    start_request(),
    httpc:request(post, {URL, Headers, ContentType, Body}, [], []).

authorized_get_request(URL, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, AuthorizationHeader).
authorized_post_request(URL, ContentType, Body, Username, Password) ->
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    perform_request(URL, [AuthorizationHeader], ContentType, Body).

%% end of httpc API

send_private_message(ZulipServer, Username, Password, Recipient, Message) ->
    send_message(ZulipServer, Username, Password, {Recipient, Message}).

send_stream_message(ZulipServer, Username, Password, Stream, Subject, Message) ->
    send_message(ZulipServer, Username, Password, {Stream, Subject, Message}).

register_message_queue(ZulipServer, Username, Password) ->
    RequestBody = lists:flatten("event_types=[\"message\"]"),
    QueueEndpoint = get_queue_endpoint(ZulipServer),
    {ok, Response} = authorized_post_request(QueueEndpoint, ?FORM_CONTENT_TYPE,
                                             RequestBody, Username, Password),
    {_, _, Data} = Response,
    RegisterResponse = jsx:decode(list_to_binary(Data)),
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
    [SenderShortName, Content] = lists:map(fun(X) -> get_key(Message, X) end,
                                                      [<<"sender_short_name">>, <<"content">>]),
    {SenderShortName, Content}.

format_message(Sender, Content) ->
    lists:flatten(io_lib:format("~s: ~s", [Sender, Content])).

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
            {error, get_key(Json, <<"msg">>)};
        _ ->
            Events = get_key(Json, <<"events">>),
            lists:map(fun get_message_with_id/1, Events)
    end.

consume_messages([{MessageID, Message} | Rest], _) ->
    {Sender, Content} = get_message(Message),
    io:format("~s~n", [format_message(Sender, Content)]),
    consume_messages(Rest, MessageID);
consume_messages([], MessageID) ->
    MessageID.

message_loop(ZulipServer, Username, Password) ->
    io:format("Started message loop~n"),
    {QueueID, LastEventID} = register_message_queue(ZulipServer, Username, Password),
    message_loop(ZulipServer, Username, Password, QueueID, LastEventID).

message_loop(ZulipServer, Username, Password, QueueID, LastEventID) ->
    receive
        _ ->
            ok
    after 1000 ->
            MessagesWithIds = check_for_messages(ZulipServer, Username, Password, QueueID, LastEventID),
            LastMessageId = consume_messages(MessagesWithIds, LastEventID),
            message_loop(ZulipServer, Username, Password, QueueID, LastMessageId)
    end.
