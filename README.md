This is a template (under 5k tokens in size), made from first principles, for:

[![janwilmake/xymake.template context](https://badge.forgithub.com/janwilmake/xymake.template?lines=false)](https://uithub.com/janwilmake/xymake.oauth-stripe-template?lines=false)

- Secure login via X OAuth
- User managment via dorm (powered by [outerbase](https://outerbase.com))

Use this boilerplate fore easy creation of apps that require X login

To use this:

- make a client at https://developer.x.com
- make sure to provide the right "User authentication settings", specifically the callback URLs should include https://your-worker.com/callback
- Ensure to get the OAuth client/secret, as highlighted below
- gather all vars in both `.dev.vars` and `wrangler.toml`, and in your deployed secrets

![](1.png)

![](2.png)

You can add as many callbacks as you want (for all your X oauthed workers)!

![](3.png)

- To explore the data in the DB: https://studio.outerbase.com/local/new-base/starbase and fill https://login.xymake.com/admin
- [Find me on X if you have any questions](https://x.com/janwilmake)

TODO:

- ✅ successfully have one db per user but with a global mirror-db
- ✅ Remove stripe webhook into separate handler for now. This'd be a different middleware.
- ✅ updated to use latest dorm version that has migrations and other better stuff. Removed stripe from template
- Make `x-oauth-template` fully oauth2.1 compatible. Use `oauth21-mcp-openapi` as guideline. Make this a middleware that takes the dorm client, and assumes a table structure.
- Implement spec of https://murlprotocol.com with this template as middleware, such that the flow becomes:
  - x login -> stripe payment -> dashboard with balance
  - login with monetaryurl with permissions
- from uithub dashboard, add monetaryurl full permission to balance via xlogin --> stripe payment
- when an uithub request is made, a murl is made first and send along into the url chain. every server deducts the desired balance afterwards.
