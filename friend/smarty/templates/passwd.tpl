{include file="header.tpl"}

<h5>CHANGE FRIEND PASSWORD:  {$smarty.server.REMOTE_USER}</h5>

<p>
    A good password should be at least six characters long and contain
    MIxeD cAsE letters, numbers, and punctuation.
</p>

<form name="f" action="/friend/passwd/" method="post"
	enctype="application/x-www-form-URLencoded">

    <p>&nbsp;</p>

    <table>
	<tr>
	    <td align="right">
		<b><label for="oldpw">Current Password</label>:</b>
	    </td>
	    <td>
		<input type="password" id="oldpw" name="oldpw"
			size="20" maxlength="60" autocomplete="off">
	    </td>
	</tr>

	<tr>
	    <td align="right">
		<b><label for="passwd0">New Password</label>:</b>
	    </td>
	    <td>
		<input type="password" id="passwd0" name="passwd0"
			size="20" maxlength="60" autocomplete="off">
	    </td>
	</tr>

	<tr>
	    <td align="right">
		<b><label for="passwd1">Confirm New Password</label>:</b>
	    </td>
	    <td>
		<input type="password" id="passwd1" name="passwd1"
			size="20" maxlength="60" autocomplete="off">
	    </td>
	</tr>

	<tr>
	    <td colspan="2" align="right">
		<input type="submit" value="Change Password">
	    </td>
	</tr>
    </table>
</form>

<p class="error">
    {$error}
</p>

{include file="footer.tpl"}


