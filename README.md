To use this:

- make a client at https://developer.x.com
- make sure to provide the right "User authentication settings", specifically the callback URLs should include https://your-worker.com/callback
- gather all vars in both .dev.vars and wrangler.jsonc, and in your deployed secrets. for stripe instructions, see https://github.com/janwilmake/stripeflare
- To explore the data in the DB: https://studio.outerbase.com/local/new-base/starbase and fill https://login.xymake.com/admin
