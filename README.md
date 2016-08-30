tuplre
=====

An OTP application, though I don't know what that is. It's actually a way to use Zulip's API via Erlang and `rebar3`
here has been kindly allowing me to do that.

Build
-----

    $ rebar3 compile

Run
---

Run a shell via `rebar3` and peruse the available functions to your heart's content

    $ rebar3 shell
    < ... Erlang shell stuff ... >
    message_loop(ZulipServer, Username, Password).

Obviously only use with a Zulip account whose private messages you won't miss, like a bot or on a development server.
