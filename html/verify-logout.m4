define( `LOGIN_ONLOAD', `1' )
include(`header.html')

<table width="95%"  border="0" align="center" cellpadding="0" cellspacing="0">
    <tr>
	<td height="487" class="maincell">
	    <table width="513"  border="0" align="center" cellpadding="0" cellspacing="0">
		<tr>
		    <td align="right" valign="middle" class="topbar"> <img src="/images/yellow_divdots.gif" width="12" height="20" align="absmiddle" class="leftbuffer"><a href="#" class="graylink">Help</a>
		    </td>
		</tr>
		<tr>
		    <td align="right" valign="top" class="dialog">
			<table width="200" height="230"  border="0" align="right" cellpadding="0" cellspacing="0" class="logobox">
			    <tr>
				<td><img src="/images/cosign_logotext.gif" width="184" height="86"></td>
			    </tr>
			    <tr>
				<td>

	<p class="maintext">
	    You are about to logout of <a class="whitelink" href="/">all weblogin
	    applications</a>.  Are you sure you want to do this?
	</p>

	<p class="maintext">
	    <form name="f" method="post" action="/cgi-bin/logout">
		<input type="button" value="Back" onClick="history.go(-1)">

		&nbsp;
		&nbsp;
		&nbsp;

		<input type="hidden" name="url" value="$u" />
		<input type="submit" name="verify" value="Logout" />
	    </form>
	</p>
				</td>
			    </tr>
			</table>
		    </td>
		</tr>
		<tr>
		    <td class="message-area"><img src="/images/icon_sysmessage.gif" width="14" height="14"> <strong>Note:</strong> After logout your browser will redirect to: $u
</td>
		</tr>
		<tr>
		    <td class="footercap">&nbsp;</td>
		</tr>
	    </table>
	</td>
    </tr>
</table>

include(`footer.html')
