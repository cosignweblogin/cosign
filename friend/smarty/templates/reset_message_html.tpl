{include file="msg_header.tpl"}

    <h5>FRIEND RESET REQUEST</h5>

    <p>
	Someone has requested that the password for your University of
	Michigan Friend account be reset.  This feature exists to allow
	you to reset your password should you happen to forget it.
    </p>

    <p>
	If you wish to reset your password, please visit the following
	link:
    </p>

    <blockquote>
	<a href="https://{$smarty.server.SERVER_NAME}/friend/reset/verify/?r={$bundle}">Reset Friend Password</a>
    </blockquote>

    <p>
	By using this service you agree to adhere to UM computing policies
	and guidelines: http://www.umich.edu/~policies/  <b>Note</b>:
	if the above link is not clickable please continue by visiting:
    </p>

    <blockquote>
	https://{$smarty.server.SERVER_NAME}/friend/reset/verify/?r={$bundle}
    </blockquote>

{include file="msg_footer.tpl"}
