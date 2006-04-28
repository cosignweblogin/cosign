// Determines if a value exists in an array
// based on code from embimedia.com
Array.prototype.inArray = function ( value )
{
    for ( var i=0; i<this.length; i++ ) {
		if ( typeof( value ) == 'object' ) {
			for ( var j=0; j<value.length; j++ ) {
				if ( this[i] === value[j] ) {
					return true;
				}
			}
		} else {
			// Matches identical (===), not just similar (==).
			if ( this[i] === value ) {
				return true;
			}
		}
    }

    return false;
};


//Remember object based on moo.fx by Valerio Proietti 
//and code by Peter-Paul Koch
var Remember = new Object();
Remember = function(){};

Remember.prototype = {
	setCookie: function( name, value ) {
		document.cookie = name + '=' + value + '; expires=Sun, 17 Jan 2038 12:34:56 UTC; path=/';
	},

	readCookie: function( name ) {
		var nameEQ = name + "=";
		var ca = document.cookie.split( ';' );
		for( var i=0; i<ca.length; i++ ) {
			var c = ca[i];
			while ( c.charAt( 0 )==' ' ) c = c.substring( 1, c.length );
			if ( c.indexOf( nameEQ ) == 0 ) {
				return {data: c.substring( nameEQ.length, c.length ), isset: true};
			}
		}

		return {data: '', isset: false};
	}
}

var Cosign = Class.create();
Cosign.prototype = Object.extend( new Remember(), {
	initialize: function( requiredFctrs ) {
		this.factorCookie    = 'exposedFactors';
		this.attribsCookie   = 'miscAttributes';
		this.factors         = Array();
		this.infoBoxes       = Array();
		this.requiredFctrs   = Array();
		this.cookieFactors   = Array();
		this.cookieAttribs   = Array();
		this.satisfied       = Array();
		this.defaultOpen     = Array();
		this.requiredFctrs   = requiredFctrs.split( ',' );
		var cookieFactors    = this.readCookie( this.factorCookie );
		this.cookieFactors   = cookieFactors.data.split( ',' );
		this.factorCookieSet = cookieFactors.isset;
		var cookieAttribs    = this.readCookie( this.attribsCookie );
		this.cookieAttribs   = cookieAttribs.data.split( ',' );
	},

	setSatisfied: function( satisfied ) {
		this.satisfied = satisfied.split( ',' );
	},

	setDefaultOpen: function( defaults ) {
		this.defaultOpen = defaults.split( ',' );
	},

	addFactor: function ( factorName, title, factorDivID ) {
		var focusBox = $( factorDivID ).getElementsByTagName( 'input' )[0];
		if ( focusBox.value != '' && focusBox.type != 'checkbox' ) {
			focusBox = $( factorDivID ).getElementsByTagName( 'input' )[1];
		}

		this.factors[title] = {factorName: factorName, title: title, factorDivID: factorDivID, focusBox: focusBox};
	},

	addInfoBox: function ( infoID, infoShow, infoHide ) {
		this.infoBoxes[infoShow] = {infoID: infoID, infoShow: infoShow, infoHide: infoHide};
	},
	
	setSubmitLink: function ( elName, formName ) {
		var submitLink = $( elName );
		Event.observe( submitLink, 'click', function() {$( formName ).submit()}, false );

		// This is old school, but Event.stop will not work in Safari as of 2.0.3...
		submitLink.onclick = function() {return false};
	},

	hide: function( factor ) {
		Effect.BlindUp( factor.factorDivID, {duration: 0.25} );
		$( factor.title ).className = 'dink';
	},

	showSatisfied: function( factor ) {
		Effect.BlindUp( factor.factorDivID, {duration: 0.25} );
		$( factor.title ).className = 'check';
		var nodes  = $( factor.title ).parentNode.childNodes;

		$A( nodes ).each(
			function( node ) {
				if ( node.className == 'authComplete' ) {
					Element.show( node );
				}
			}
		);
	},

	giveFocus: function( focusBox ) {
		try {
			$( focusBox ).focus();
			return true;
		} catch ( e ) {
			return false;
		}
	},

	toggle: function( factor ) {
		var blindStart = function() {
			if ( $( factor.factorDivID ).style.display == 'none' ) {
				$( factor.title ).className = 'dinkDown';
			} else {
				$( factor.title ).className = 'dink';
			}
		};

		var blindFinish = function() {
			this.saveFactorState( factor );
			this.closeInfo();
		}.bind(this);

		Effect.toggle( factor.factorDivID, 'blind', {duration: 0.25, beforeStart: blindStart, afterFinish: blindFinish} );
	},

	// Based on http://www.howtocreate.co.uk/jslibs/capsDetect.js
	capsDetect: function ( e ) {
		if( !e ) {
			e = window.event;
		}

		if( !e ) {
			this.MWJ_say_Caps( false );
			return;
		}

		//what (case sensitive in good browsers) key was pressed
		var theKey = e.which ? e.which : ( e.keyCode ? e.keyCode : ( e.charCode ? e.charCode : 0 ));
		//if upper case, check if shift is not pressed. if lower case, check if shift is pressed
		this.MWJ_say_Caps(( theKey > 64 && theKey < 91 && ! e.shiftKey ) || ( theKey > 96 && theKey < 123 && e.shiftKey ));
	},

	MWJ_say_Caps: function( oC ) {
		var elements = document.getElementsByClassName( 'capsLock' );
		if( oC ) {
			elements.each( function( node ) {Element.show( node )} );
		} else {
			elements.each( function( node ) {Element.hide( node )} );
		}
	},

	initUI: function() {
		var oThis    = this;
		var focusSet = false;
		
		// Don't set focus if user has already clicked or typed
		Event.observe( window, 'click', function() {focusSet = true} );
		Event.observe( window, 'keydown', function() {focusSet = true} );

		// escape framesets
		if ( window != top ) {
			top.location.href = location.href;
		}

		if ( $( 'error' ) != null ) {
			new Effect.Highlight( 'error' );
		}
		
		var nodeList  = document.getElementsByTagName( 'input' );
		var nodes     = $A( nodeList );

		nodes.each( function( node ) {
				// The Scriptaculous Event.Observe method cannot be used here.
				// Most browsers will not capture the event properly with it.
				if ( node.type == 'password') {
					node.onkeypress = function( e ){oThis.capsDetect( e )};
					node.setAttribute( 'autocomplete', 'off' );
				} else if ( node.type == 'text' ) {
					node.setAttribute( 'autocomplete', 'off' );
				}
			});

		// Set factor visibility and focus
		$H( this.factors ).each( function( factor ) {
			if ( this.satisfied.inArray( factor.value.factorName )) {
				this.showSatisfied( factor.value );
			} else if ( this.requiredFctrs.inArray( factor.value.factorName )) {
				$( factor.value.title ).className = 'required';
				if ( ! focusSet ) {
					focusSet = this.giveFocus( factor.value.focusBox );
				}
			} else if ( this.cookieFactors.inArray( factor.value.factorName )) {
				Event.observe(factor.key, 'click', function(){oThis.toggle(oThis.factors[factor.key])});
				if ( ! focusSet ) {
					focusSet = this.giveFocus( factor.value.focusBox );
				}
			} else if ( this.defaultOpen.inArray( factor.value.factorName ) && this.factorCookieSet == false ) {
				Event.observe(factor.key, 'click', function(){oThis.toggle(oThis.factors[factor.key])});
				if ( ! focusSet ) {
					focusSet = this.giveFocus( factor.value.focusBox );
				}

				// Set a cookie for the default open factor
				this.saveFactorState( factor.value );
			} else {
				Event.observe(factor.key, 'click', function(){oThis.toggle(oThis.factors[factor.key])});
				this.hide( factor.value );
			}
		}.bind( this ));

		// Register InfoBox click events
		$H( this.infoBoxes ).each( function( infoBox ) {
			Event.observe(infoBox.key, 'click', function(){oThis.showInfo(oThis.infoBoxes[infoBox.key].infoID)});
			Event.observe(infoBox.value.infoHide, 'click', function(){oThis.closeInfo()});
			Element.hide( infoBox.value.infoID );
			$( infoBox.value.infoID ).style.visibility = 'visible'; // Prevents a "flash" of all infoboxes on load
		});

		// Apply misc element attributes
		for ( var i=0; i<this.cookieAttribs.length; i++ ) {
			var attrib = this.cookieAttribs[i].split( '~' );
			if ( attrib.length == 3 ) {
				var el = $( attrib[0] );
				if ( el != null ) {
					el.setAttribute( attrib[1], attrib[2] );
				}
			}
		}
	},

	saveFactorState: function( factor ) {
		if ( $( factor.factorDivID ).style.display != 'none' && ! this.cookieFactors.inArray( factor.factorName )) {
			if ( typeof( factor.factorName ) == 'object' ) {
				this.cookieFactors.push( factor.factorName[0] ); // Some factors have multiple names
			} else {
				this.cookieFactors.push( factor.factorName );
			}
		} else if ( typeof( factor.factorName ) == 'object' ) {
			for ( var i=0; i<this.cookieFactors.length; i++ ) {
				if ( factor.factorName.inArray( this.cookieFactors[i] )) {
					this.cookieFactors.splice( i, 1 );
				}
			}
		} else {
			for ( var i=0; i<this.cookieFactors.length; i++ ) {
				if ( this.cookieFactors[i] == factor.factorName ) {
					this.cookieFactors.splice( i, 1 );
				}
			}
		}

		this.setCookie( this.factorCookie, this.cookieFactors.join());
	},

	saveAttribute: function( id, atName, atValue ) {
		for ( var i=0; i<this.cookieAttribs.length; i++ ) {
			if ( this.cookieAttribs[i].indexOf( id + '~' + atName ) != -1 ) {
				this.forgetAttribute( id, atName );
			}
		}

		this.cookieAttribs.push( id + '~' + atName + '~' + atValue );
		this.setCookie( this.attribsCookie, this.cookieAttribs.join());
	},

	forgetAttribute: function( id, atName ) {
		for ( var i=0; i<this.cookieAttribs.length; i++ ) {
			if ( this.cookieAttribs[i].indexOf( id + '~' + atName ) != -1 ) {
				this.cookieAttribs.splice( i, 1 );
			}
		}

		this.setCookie( this.attribsCookie, this.cookieAttribs.join());
	},

	closeInfo: function() {
		var fades = Array();
		$H( this.infoBoxes ).each( function(infoBox ) {
			fades.push( Effect.Fade( infoBox.value.infoID ));
		});

		new Effect.Parallel( fades, {duration: 0.20} );
	},

	showInfo: function( showInfoID ) {
		var fades = Array();
		$H( this.infoBoxes ).each( function( infoBox ) {
			if ( infoBox.value.infoID != showInfoID ) {
				fades.push( Effect.Fade( infoBox.value.infoID ));
			}
		});

		new Effect.Parallel(fades,{duration: 0.20, afterFinish: function(){Effect.Appear(showInfoID,{duration: 0.20});}});
		
	},

	enDisableCheck: function( trigger, inputEl, label ) {
		var trigger = $( trigger );

		if ( trigger.checked ) {
			$( inputEl ).setAttribute( 'disabled', 'disabled' );
			$( inputEl ).value='';
			$( label ).setAttribute( 'disabled', 'disabled' ); // ie
			$( label ).setAttribute( 'style', 'color: #999' ); // others
			this.saveAttribute( inputEl, 'disabled', 'disabled' );
			this.saveAttribute( label, 'disabled', 'disabled' );
			this.saveAttribute( label, 'style', 'color: #999' );
			this.saveAttribute( trigger.id, 'checked', 'checked' );
		} else {
			$( inputEl ).removeAttribute( 'disabled' );
			$( label ).removeAttribute( 'disabled' ); // ie
			$( label ).removeAttribute( 'style' ); // others
			this.forgetAttribute( inputEl, 'disabled' );
			this.forgetAttribute( label, 'disabled' );
			this.forgetAttribute( label, 'style' );
			this.forgetAttribute( trigger.id, 'checked' );
		}
	},

	enDisableKey: function( trigger, inputEl, label ) {
		var trigger = $( trigger );

		if ( trigger.value.length > 0 ) {
			$( inputEl ).setAttribute( 'disabled', 'disabled' );
			$( label ).setAttribute( 'disabled', 'disabled' ); // ie
			$( label ).setAttribute( 'style', 'color: #999' ); // others
		} else {
			$( inputEl ).removeAttribute( 'disabled' );
			$( label ).removeAttribute( 'disabled' ); // ie
			$( label ).removeAttribute( 'style' ); // others
		}
	}
});
