define( `LOGIN_ONLOAD', `1' )
include(`header.html')

<!-- if you change the action to a subdir, be sure it ends 
    in a / e.g.  /login/ -->
<form name="f" action="/"
	enctype="application/x-www-form-urlencoded"
		method="post" autocomplete="off">
		<input type="hidden" name="ref" value="$r">
		<input type="hidden" name="service" value="$c">

<table width="95%"  border="0" align="center" cellpadding="0" cellspacing="0">
    <tr>
	<td height="487" class="maincell">
	    <table width="513"  border="0" align="center" cellpadding="0" cellspacing="0">
		<tr>
		    <td align="right" valign="middle" class="topbar"> <img src="images/yellow_divdots.gif" width="12" height="20" align="absmiddle" class="leftbuffer"><a href="#" class="graylink"> Forgotten Password? </a> <img src="images/yellow_divdots.gif" width="12" height="20" align="absmiddle" class="leftbuffer"><a href="#" class="graylink">Request an Account</a> <img src="images/yellow_divdots.gif" width="12" height="20" align="absmiddle" class="leftbuffer"><a href="#" class="graylink">Help</a>
		    </td>
		</tr>
		<tr>
		    <td align="right" valign="top" class="dialog">
			<table width="200" height="230"  border="0" align="right" cellpadding="0" cellspacing="0" class="logobox">
			    <tr>
				<td><img src="images/cosign_logotext.gif" width="184" height="86"></td>
			    </tr>
			    <tr>
				<td>
				    <table width="150"  border="0" cellpadding="0" cellspacing="0" class="formbox">
					<tr>
					    <td>&nbsp;</td>
					    <td><img src="images/username_graphic.gif" width="53" height="15"></td>
					    <td>&nbsp;</td>
					</tr>
					<tr>
					    <td rowspan="4" valign="middle"><img src="images/bracket_left.gif" width="12" height="60" hspace="4"></td>
					    <td><input type="text" id="login" name="login" size="15" value="$l"></td>
					    <td rowspan="4" valign="middle"><img src="images/bracket_right.gif" width="12" height="60" hspace="4"></td>
					</tr>
					<tr>
					    <td><img src="images/spacer.gif" width="1" height="8"></td>
					</tr>
					<tr>
					    <td><img src="images/password_text.gif" width="53" height="15"></td>
					</tr>
					<tr>
					    <td><input value="" size="15" id="password" name="password" type="password" autocomplete="off"></td>
					</tr>
				    </table>
				</td>
			    </tr>
			    <tr>
				<td align="right"><input name="imageField" type="image" src="images/login_anim_fd.gif" width="83" height="34" border="0"></td>
			    </tr>
			</table>
		    </td>
		</tr>
		<tr>
		    <td class="message-area"><img src="images/icon_alert.gif" width="14" height="14"> <strong>$t:</strong> $e </td>
		</tr>
		<tr>
		    <td class="footercap">&nbsp;</td>
		</tr>
	    </table>
	</td>
    </tr>
</table>

include(`footer.html')
