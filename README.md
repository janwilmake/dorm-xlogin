This is a template (under 5k tokens in size), made from first principles, for:

[![janwilmake/xymake.template context](https://badge.forgithub.com/janwilmake/xymake.template)](https://uithub.com/janwilmake/xymake.oauth-stripe-template)

- Secure login via X OAuth
- User managment via dorm (powered by [outerbase](https://outerbase.com))
- Stripe payment processing (powered by [stripeflare](https://github.com/janwilmake/stripeflare))

Use this boilerplate fore easy creation of apps with subscribers or features behind one-time payment.

To use this:

- make a client at https://developer.x.com
- make sure to provide the right "User authentication settings", specifically the callback URLs should include https://your-worker.com/callback
- gather all vars in both .dev.vars and wrangler.jsonc, and in your deployed secrets. for stripe instructions, see https://github.com/janwilmake/stripeflare
- To explore the data in the DB: https://studio.outerbase.com/local/new-base/starbase and fill https://login.xymake.com/admin

[Find me on X](https://x.com/janwilmake)

TODO:

- ✅ successfully have one db per user but with a global mirror-db

- ✅ Remove stripe webhook into separate handler for now. This'd be a different middleware.

- Make `x-oauth-template` fully oauth2.1 compatible. Use `oauth21-mcp-openapi` as guideline. Make this a middleware that takes the dorm client, and assumes a table structure.

- Implement spec of https://murlprotocol.com with this template as middleware, such that the flow becomes:

  - x login -> stripe payment -> dashboard with balance
  - login with monetaryurl with permissions

- from uithub dashboard, add monetaryurl full permission to balance via xlogin --> stripe payment

- when an uithub request is made, a murl is made first and send along into the url chain. every server deducts the desired balance afterwards.
