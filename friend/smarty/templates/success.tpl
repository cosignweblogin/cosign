{include file="header.tpl"}

<h5>FRIEND ACCOUNT : SUCCESS </h5>
<br />

<p>
    Your new Friend account has been created with the login id:
</p>

<p>
    <blockquote>
	<b>{$login|escape}</b>
    </blockquote>
</p>

<p>
    You will receive a confirmation e-mail message with links to our
    password changing and password reset web sites in a few moments.
    The next step is to login and begin using your new account:
</p>

<p>
    <blockquote>
	<a href="{$destination|escape}">login using your new login and password now</a>.
    </blockquote>
</p>

{include file="footer.tpl"}
