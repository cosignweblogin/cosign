{include file="header.tpl"}

<h5>REQUEST A FRIEND ACCOUNT</h5>
<form name="f" action="/friend/" method="post"
	enctype="application/x-www-form-URLencoded">

    <p><label for="email">By using this service you agree to adhere to <a href="http://www.umich.edu/~policies/">UM computing policies and guidelines</a>.  Please enter your email address.  This will be your Friend guest login id</label>:</p>
    <input id="email" name="email" size="50" maxlength="60" value="{$email}">

    <input type="submit" value="Request">
</form>
<br />
<p class="error">
    {$error}
</p>

<p>
    <b>Please note</b>: Friend account creation and login require that
    your browser accept 'cookies.'  Please see your browser's
    documentation or help system for assistance enabling cookies.
</p>

{include file="footer.tpl"}
