{include file="header.tpl"}

<h5>FRIEND ACCOUNT : PASSWORD CHANGED </h5>
<br />

<p>
    Your Friend password has been changed for your account:
</p>

<p>
    <blockquote>
	<b>{$smarty.server.REMOTE_USER}</b>
    </blockquote>
</p>

<p>
    We recommend that you <a
    href="/cgi-bin/logout?https://{$smarty.server.SERVER_NAME}/">test
    your new password</a> by logging out and then logging back-in now.
</p>

<p>
    If, for some reason, you are unable to login with your new password,
    you can always reset it by following the "Reset your Friend password"
    link from our login screen.
</p>

{include file="footer.tpl"}
