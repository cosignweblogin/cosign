{include file="msg_header.tpl"}

    <h5>
	FRIEND ACCOUNT CREATED
    </h5>

    <p>
	Thank you for creating a new U of M Friend guest account.
	Please visit the following URL to login with this new account:
    </p>

    <blockquote>
	<a href="https://{$smarty.server.SERVER_NAME}/">https://{$smarty.server.SERVER_NAME}/</a>
    </blockquote>

    <p>
	Your login name is: <b>{$login}</b>
    </p>

    <p>
	Your password is whatever you just set it to;  you can change
	it to a new password by visiting:
    </p>

    <blockquote>
	<a href="https://{$smarty.server.SERVER_NAME}/friend/passwd/">https://{$smarty.server.SERVER_NAME}/friend/passwd/</a>
    </blockquote>

    <p>
	If you forget your password at any point you can reset it to
	something you know by visiting:
    </p>

    <blockquote>
	<a href="https://{$smarty.server.SERVER_NAME}/friend/reset/">https://{$smarty.server.SERVER_NAME}/friend/reset/</a>
    </blockquote>

    <p>
	Questions about access to specific protected web sites at the
	University of Michigan should be directed to the maintainers of
	those sites.  You may find it helpful to keep this message for
	future reference.
    </p>

{include file="msg_footer.tpl"}
