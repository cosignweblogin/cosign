define( `LOGOUT_ONLOAD', `1' )
include(`header.html')

	<td valign="top">
            <p>
		Are you sure you want to quit all UM web applications
		and log out now?
            </p>

            <p class="small">
		Click 'Logout' or press the return key to end your
		session.
            </p>

            <p align="right">
		<form name="f" method="post" action="/cgi-bin/logout">
		    <input type="submit" value="Cancel" />

		    &nbsp;
		    &nbsp;
		    &nbsp;

		    <input type="hidden" name="url" value="$l" />
		    <input type="submit" name="verify" value="Logout" />
		</form>
            </p>
	</td>

include(`footer.html')
