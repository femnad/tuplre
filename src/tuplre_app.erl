%%%-------------------------------------------------------------------
%% @doc tuplre public API
%% @end
%%%-------------------------------------------------------------------

-module(tuplre_app).

-behaviour(application).

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
    case EndpointType of messages ->
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

get_basic_authorization_header(Username, Password) ->
    UsernameAndPassword = lists:flatten(io_lib:format("~s:~s", [Username, Password])),
    Base64Encoded = base64:encode_to_string(UsernameAndPassword),
    {"Authorization", lists:flatten(io_lib:format("Basic ~s", [Base64Encoded]))}.

format_key_value(K, V) ->
    io_lib:format("~s=~s", [K, V]).

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
    inets:start(),
    ssl:start(),
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    RequestBody = get_request_body(MessageComponents),
    perform_request(post, get_messages_endpoint(ZulipServer),
                    [AuthorizationHeader], "application/x-www-form-urlencoded",
                    RequestBody).

perform_request(Method, URL, Headers, ContentType, Body) ->
    inets:start(),
    ssl:start(),
    Result = httpc:request(Method, {URL, Headers, ContentType, Body}, [], []),
    case Result of
        {ok, Response} ->
            Response;
        {error, Response} ->
            {error, Response}
    end.

send_private_message(ZulipServer, Username, Password, Recipient, Message) ->
    send_message(ZulipServer, Username, Password, {Recipient, Message}).

send_stream_message(ZulipServer, Username, Password, Stream, Subject, Message) ->
    send_message(ZulipServer, Username, Password, {Stream, Subject, Message}).

make_authorized_request(Endpoint, Username, Password, Method) ->
    inets:start(),
    ssl:start(),
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    case Method of get ->
            {ok, {_, _, Data}} = httpc:request(get, {Endpoint, [AuthorizationHeader]}, [], []),
            Data;
        _ ->
            hi
    end.

register_message_queue(ZulipServer, Username, Password) ->
    inets:start(),
    ssl:start(),
    AuthorizationHeader = get_basic_authorization_header(Username, Password),
    RequestBody = lists:flatten("event_types=[\"message\"]"),
    QueueEndpoint = get_queue_endpoint(ZulipServer),
    {ok, Response} = httpc:request(post, {QueueEndpoint,
                                        [AuthorizationHeader],
                                        "application/x-www-form-urlencoded",
                                        RequestBody}, [], []),
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
    EventsEndpoint = lists:flatten(io_lib:format("~s?queue_id=~s&last_event_id=~w&dont_block=true",
                                                 [get_events_endpoint(ZulipServer),
                                                  QueueID, LastEventID])),
    Response = make_authorized_request(EventsEndpoint, Username, Password, get),
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
    MessagesWithIds = check_for_messages(ZulipServer, Username, Password, QueueID, LastEventID),
    LastMessageId = consume_messages(MessagesWithIds, LastEventID),
    timer:sleep(1000),
    message_loop(ZulipServer, Username, Password, QueueID, LastMessageId).
