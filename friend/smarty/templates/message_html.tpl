{include file="msg_header.tpl"}

    <h5>
	FRIEND ACCOUNT CREATION
    </h5>

    <p>
	Someone has requested that your e-mail address be used as the
	account name for a new University of Michigan 'Friend' account.
	If you would like to continue the account creation process,
	please visit the following link:
    </p>

    <blockquote>
	<a href="https://{$smarty.server.SERVER_NAME}/friend/create/?r={$bundle}"><b>Create Friend Account</b></a>
    </blockquote>

    <p>
	This new account will grant you access to a number of web-based
	resources at the University of Michigan.  By using this service
	you agree to adhere to UM computing policies and guidelines: <a href="http://www.umich.edu/~policies/">http://www.umich.edu/~policies/</a>
    </p>

    <p>
	<b>Note</b>: if the creation link is not clickable please continue
	by visiting:
    </p>

    <blockquote>
	https://{$smarty.server.SERVER_NAME}/friend/create/?r={$bundle}
    </blockquote>

{include file="msg_footer.tpl"}
