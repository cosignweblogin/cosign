{include file="header.tpl"}

<h5>RESET FRIEND PASSWORD</h5>
<form name="f" action="/friend/reset/" method="post"
	enctype="application/x-www-form-URLencoded">

    <p>&nbsp;</p>

    <p><label for="email">Enter your email address/Friend login id to request a password reset</label>:</p>
    <input id="email" name="email" size="50" maxlength="60" value="{$email}">

    <input type="submit" value="Request">
</form>
<br />
<p class="error">
    {$error}
</p>

<p>
    You will be e-mailed a link to the password-reset page.  Follow that
    link to reset your guest account password.
</p>

{include file="footer.tpl"}
