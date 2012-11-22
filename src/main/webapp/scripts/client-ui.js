
/**
 * Client UI root object.
 */
GuacUI.Client = {

    /**
     * Collection of all Guacamole client UI states.
     */
    "states": {

        /**
         * The normal default Guacamole client UI mode
         */
        "INTERACTIVE" : 0,

        /**
         * Same as INTERACTIVE except with visible on-screen keyboard.
         */
        "OSK"              : 1,

        /**
         * No on-screen keyboard, but a visible magnifier.
         */
        "MAGNIFIER"        : 2,

        /**
         * Arrows and a draggable view.
         */
        "PAN"              : 3,

        /**
         * Same as PAN, but with visible native OSK.
         */
        "PAN_TYPING"       : 4
    },

    /* Constants */
    
    "LONG_PRESS_DETECT_TIMEOUT"     : 800, /* milliseconds */
    "LONG_PRESS_MOVEMENT_THRESHOLD" : 10,  /* pixels */    
    "KEYBOARD_AUTO_RESIZE_INTERVAL" : 30,  /* milliseconds */

    /* UI Components */

    "viewport"    : document.getElementById("viewportClone"),
    "display"     : document.getElementById("display"),
    "logo"        : document.getElementById("status-logo"),

    "buttons": {
        "reconnect" : document.getElementById("reconnect")
    },

    "containers": {
        "state"     : document.getElementById("statusDialog"),
        "keyboard"  : document.getElementById("keyboardContainer")
    },
    
    "state"        : document.getElementById("statusText"),
    "client"       : null,

    /* Expected Input Rectangle */

    "expected_input_x" : 0,
    "expected_input_y" : 0,
    "expected_input_width" : 1,
    "expected_input_height" : 1

};

// Tie UI events / behavior to a specific Guacamole client
GuacUI.Client.attach = function(guac) {

    GuacUI.client = guac;

    var title_prefix = null;
    var connection_name = "Guacamole"; 
    
    var guac_display = guac.getDisplay();

    // Set document title appropriately, based on prefix and connection name
    function updateTitle() {

        // Use title prefix if present
        if (title_prefix) {
            
            document.title = title_prefix;

            // Include connection name, if present
            if (connection_name)
                document.title += " " + connection_name;

        }

        // Otherwise, just set to connection name
        else if (connection_name)
            document.title = connection_name;

    }

    guac_display.onclick = function(e) {
        e.preventDefault();
        return false;
    };

    // Mouse
    var mouse = new Guacamole.Mouse(guac_display);
    var touch = new Guacamole.Mouse.Touchpad(guac_display);
    touch.onmousedown = touch.onmouseup = touch.onmousemove =
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove =
        function(mouseState) {
       
            // Determine mouse position within view
            var mouse_view_x = mouseState.x + guac_display.offsetLeft - window.pageXOffset;
            var mouse_view_y = mouseState.y + guac_display.offsetTop  - window.pageYOffset;

            // Determine viewport dimensioins
            var view_width  = GuacUI.Client.viewport.offsetWidth;
            var view_height = GuacUI.Client.viewport.offsetHeight;

            // Determine scroll amounts based on mouse position relative to document

            var scroll_amount_x;
            if (mouse_view_x > view_width)
                scroll_amount_x = mouse_view_x - view_width;
            else if (mouse_view_x < 0)
                scroll_amount_x = mouse_view_x;
            else
                scroll_amount_x = 0;

            var scroll_amount_y;
            if (mouse_view_y > view_height)
                scroll_amount_y = mouse_view_y - view_height;
            else if (mouse_view_y < 0)
                scroll_amount_y = mouse_view_y;
            else
                scroll_amount_y = 0;

            // Scroll (if necessary) to keep mouse on screen.
            window.scrollBy(scroll_amount_x, scroll_amount_y);

            // Scale event by current scale
            var scaledState = new Guacamole.Mouse.State(
                    mouseState.x / guac.getScale(),
                    mouseState.y / guac.getScale(),
                    mouseState.left,
                    mouseState.middle,
                    mouseState.right,
                    mouseState.up,
                    mouseState.down);

            // Send mouse event
            guac.sendMouseState(scaledState);
            
        };

    // Keyboard
    var keyboard = new Guacamole.Keyboard(document);
    var show_keyboard_gesture_possible = true;

    keyboard.onkeydown = function (keysym) {
        guac.sendKeyEvent(1, keysym);

        // If key is NOT one of the expected keys, gesture not possible
        if (keysym != 0xFFE3 && keysym != 0xFFE9 && keysym != 0xFFE1)
            show_keyboard_gesture_possible = false;

    };

    keyboard.onkeyup = function (keysym) {
        guac.sendKeyEvent(0, keysym);

        // If lifting up on shift, toggle keyboard if rest of gesture
        // conditions satisfied
        if (show_keyboard_gesture_possible && keysym == 0xFFE1) {
            if (keyboard.pressed[0xFFE3] && keyboard.pressed[0xFFE9]) {

                // If in INTERACTIVE mode, switch to OSK
                if (GuacUI.StateManager.getState() == GuacUI.Client.states.INTERACTIVE)
                    GuacUI.StateManager.setState(GuacUI.Client.states.OSK);

                // If in OSK mode, switch to INTERACTIVE 
                else if (GuacUI.StateManager.getState() == GuacUI.Client.states.OSK)
                    GuacUI.StateManager.setState(GuacUI.Client.states.INTERACTIVE);

            }
        }

        // Detect if no keys are pressed
        var reset_gesture = true;
        for (var pressed in keyboard.pressed) {
            reset_gesture = false;
            break;
        }

        // Reset gesture state if possible
        if (reset_gesture)
            show_keyboard_gesture_possible = true;

    };

    function isTypableCharacter(keysym) {
        return (keysym & 0xFFFF00) != 0xFF00;
    }

    function updateThumbnail() {

        // Get screenshot
        var canvas = guac.flatten();

        // Calculate scale of thumbnail (max 320x240, max zoom 100%)
        var scale = Math.min(
            320 / canvas.width,
            240 / canvas.height,
            1
        );

        // Create thumbnail canvas
        var thumbnail = document.createElement("canvas");
        thumbnail.width  = canvas.width*scale;
        thumbnail.height = canvas.height*scale;

        // Scale screenshot to thumbnail
        var context = thumbnail.getContext("2d");
        context.drawImage(canvas,
            0, 0, canvas.width, canvas.height,
            0, 0, thumbnail.width, thumbnail.height
        );

        // Save thumbnail to history
        var id = decodeURIComponent(window.location.search.substring(4));
        GuacamoleHistory.update(id, thumbnail.toDataURL());

    }

    function updateDisplayScale() {

        // If auto-fit is enabled, scale display
        if (GuacUI.sessionState.getProperty("auto-fit")) {

            // Calculate scale to fit screen
            var fit_scale = Math.min(
                window.innerWidth / guac.getWidth(),
                window.innerHeight / guac.getHeight()
            );
              
            // Scale client
            if (fit_scale != guac.getScale())
                guac.scale(fit_scale);

        }

        // Otherwise, scale to 100%
        else if (guac.getScale() != 1.0)
            guac.scale(1.0);

    }

    // Handle resize
    guac.onresize = function(width, height) {
        updateDisplayScale();
    }

    var last_status_notification = null;
    function hideStatus() {
        if (last_status_notification)
            last_status_notification.hide();
        last_status_notification = null;
    }

    function showStatus(status) {
        hideStatus();

        last_status_notification = new GuacUI.Client.ModalStatus(status);
        last_status_notification.show();
    }

    function showError(status) {
        hideStatus();

        last_status_notification = new GuacUI.Client.ModalStatus(status);
        last_status_notification.show();
    }

    // Handle client state change
    guac.onstatechange = function(clientState) {

        switch (clientState) {

            // Idle
            case 0:
                showStatus("Idle.");
                title_prefix = "[Idle]";
                break;

            // Connecting
            case 1:
                showStatus("Connecting...");
                title_prefix = "[Connecting...]";
                break;

            // Connected + waiting
            case 2:
                showStatus("Connected, waiting for first update...");
                title_prefix = "[Waiting...]";
                break;

            // Connected
            case 3:

                hideStatus();
                title_prefix = null;

                // Update clipboard with current data
                if (GuacUI.sessionState.getProperty("clipboard"))
                    guac.setClipboard(GuacUI.sessionState.getProperty("clipboard"));

                // Regularly update screenshot
                window.setInterval(updateThumbnail, 1000);

                break;

            // Disconnecting
            case 4:
                showStatus("Disconnecting...");
                title_prefix = "[Disconnecting...]";
                break;

            // Disconnected
            case 5:
                showStatus("Disconnected.");
                title_prefix = "[Disconnected]";
                break;

            // Unknown status code
            default:
                showStatus("[UNKNOWN STATUS]");

        }

        updateTitle();
    };

    // Name instruction handler
    guac.onname = function(name) {
        connection_name = name;
        updateTitle();
    };

    // Error handler
    guac.onerror = function(error) {

        // Disconnect, if connected
        guac.disconnect();

        // Display error message
        showError(error);
        
    };

    // Disconnect and update thumbnail on close
    window.onunload = function() {

        updateThumbnail();
        guac.disconnect();

    };

    // Send size events on resize
    window.onresize = function() {

        guac.sendSize(window.innerWidth, window.innerHeight);
        updateDisplayScale();

    };

    // Server copy handler
    guac.onclipboard = function(data) {
        GuacUI.sessionState.setProperty("clipboard", data);
    };

    GuacUI.sessionState.onchange = function(old_state, new_state, name) {
        if (name == "clipboard")
            guac.setClipboard(new_state[name]);
        else if (name == "auto-fit")
            updateDisplayScale();

    };

    var long_press_start_x = 0;
    var long_press_start_y = 0;
    var longPressTimeout = null;

    GuacUI.Client.startLongPressDetect = function() {

        if (!longPressTimeout) {

            longPressTimeout = window.setTimeout(function() {
                longPressTimeout = null;
                if (GuacUI.Client.client.getScale() != 1.0)
                    GuacUI.StateManager.setState(GuacUI.Client.states.MAGNIFIER);
                else
                    GuacUI.StateManager.setState(GuacUI.Client.states.PAN);
            }, GuacUI.Client.LONG_PRESS_DETECT_TIMEOUT);

        }
    };

    GuacUI.Client.stopLongPressDetect = function() {
        window.clearTimeout(longPressTimeout);
        longPressTimeout = null;
    };

    // Detect long-press at bottom of screen
    GuacUI.Client.display.addEventListener('touchstart', function(e) {
        
        // Record touch location
        if (e.touches.length == 1) {
            var touch = e.touches[0];
            long_press_start_x = touch.screenX;
            long_press_start_y = touch.screenY;
        }
        
        // Start detection
        GuacUI.Client.startLongPressDetect();
        
    }, true);

    // Stop detection if touch moves significantly
    GuacUI.Client.display.addEventListener('touchmove', function(e) {
        
        // If touch distance from start exceeds threshold, cancel long press
        var touch = e.touches[0];
        if (Math.abs(touch.screenX - long_press_start_x) >= GuacUI.Client.LONG_PRESS_MOVEMENT_THRESHOLD
            || Math.abs(touch.screenY - long_press_start_y) >= GuacUI.Client.LONG_PRESS_MOVEMENT_THRESHOLD)
            GuacUI.Client.stopLongPressDetect();
        
    }, true);

    // Stop detection if press stops
    GuacUI.Client.display.addEventListener('touchend', GuacUI.Client.stopLongPressDetect, true);

};

/**
 * Component which displays a magnified (100% zoomed) client display.
 * 
 * @constructor
 * @augments GuacUI.DraggableComponent
 */
GuacUI.Client.Magnifier = function() {

    /**
     * Reference to this magnifier.
     * @private
     */
    var guac_magnifier = this;

    /**
     * Large background div which will block touch events from reaching the
     * client while also providing a click target to deactivate the
     * magnifier.
     * @private
     */
    var magnifier_background = GuacUI.createElement("div", "magnifier-background");

    /**
     * Container div for the magnifier, providing a clipping rectangle.
     * @private
     */
    var magnifier = GuacUI.createChildElement(magnifier_background,
        "div", "magnifier");

    /**
     * Canvas which will contain the static image copy of the display at time
     * of show.
     * @private
     */
    var magnifier_display = GuacUI.createChildElement(magnifier, "canvas");

    /**
     * Context of magnifier display.
     * @private
     */
    var magnifier_context = magnifier_display.getContext("2d");

    /*
     * This component is draggable.
     */
    GuacUI.DraggableComponent.apply(this, [magnifier]);

    // Ensure transformations on display originate at 0,0
    magnifier.style.transformOrigin =
    magnifier.style.webkitTransformOrigin =
    magnifier.style.MozTransformOrigin =
    magnifier.style.OTransformOrigin =
    magnifier.style.msTransformOrigin =
        "0 0";

    /*
     * Reposition magnifier display relative to own position on screen.
     */

    this.onmove = function(x, y) {

        var width = magnifier.offsetWidth;
        var height = magnifier.offsetHeight;

        // Update contents relative to new position
        var clip_x = x
            / (window.innerWidth - width) * (GuacUI.Client.client.getWidth() - width);
        var clip_y = y
            / (window.innerHeight - height) * (GuacUI.Client.client.getHeight() - height);
       
        magnifier_display.style.WebkitTransform =
        magnifier_display.style.MozTransform =
        magnifier_display.style.OTransform =
        magnifier_display.style.msTransform =
        magnifier_display.style.transform = "translate("
            + (-clip_x) + "px, " + (-clip_y) + "px)";

        /* Update expected input rectangle */
        GuacUI.Client.expected_input_x = clip_x;
        GuacUI.Client.expected_input_y = clip_y;
        GuacUI.Client.expected_input_width  = width;
        GuacUI.Client.expected_input_height = height;

    };

    /*
     * Copy display and add self to body on show.
     */

    this.show = function() {

        // Copy displayed image
        magnifier_display.width = GuacUI.Client.client.getWidth();
        magnifier_display.height = GuacUI.Client.client.getHeight();
        magnifier_context.drawImage(GuacUI.Client.client.flatten(), 0, 0);

        // Show magnifier container
        document.body.appendChild(magnifier_background);

    };

    /*
     * Remove self from body on hide.
     */

    this.hide = function() {

        // Hide magnifier container
        document.body.removeChild(magnifier_background);

    };

    /*
     * If the user clicks on the background, switch to INTERACTIVE mode.
     */

    magnifier_background.addEventListener("click", function() {
        GuacUI.StateManager.setState(GuacUI.Client.states.INTERACTIVE);
    }, true);

    /*
     * If the user clicks on the magnifier, switch to PAN_TYPING mode.
     */

    magnifier.addEventListener("click", function(e) {
        GuacUI.StateManager.setState(GuacUI.Client.states.PAN_TYPING);
        e.stopPropagation();
    }, true);

};

/*
 * We inherit from GuacUI.DraggableComponent.
 */
GuacUI.Client.Magnifier.prototype = new GuacUI.DraggableComponent();

GuacUI.StateManager.registerComponent(
    new GuacUI.Client.Magnifier(),
    GuacUI.Client.states.MAGNIFIER
);

/**
 * Zoomed Display, a pseudo-component.
 * 
 * @constructor
 * @augments GuacUI.Component
 */
GuacUI.Client.ZoomedDisplay = function() {

    var old_scale = null;

    this.show = function() {
        old_scale = GuacUI.Client.client.getScale();
        GuacUI.Client.client.scale(1.0);
    };

    this.hide = function() {
        GuacUI.Client.client.scale(old_scale);
    };

};

GuacUI.Client.ZoomedDisplay.prototype = new GuacUI.Component();

/*
 * Zoom the main display during PAN and PAN_TYPING modes.
 */

GuacUI.StateManager.registerComponent(
    new GuacUI.Client.ZoomedDisplay(),
    GuacUI.Client.states.PAN,
    GuacUI.Client.states.PAN_TYPING
);

/**
 * Pan overlay UI. This component functions to receive touch events and
 * translate them into scrolling of the main UI.
 * 
 * @constructor
 * @augments GuacUI.Component
 */
GuacUI.Client.PanOverlay = function() {

    /**
     * Overlay which will provide the means of scrolling the screen.
     */
    var pan_overlay = GuacUI.createElement("div", "pan-overlay");

    /*
     * Add arrows
     */

    GuacUI.createChildElement(pan_overlay, "div", "indicator up");
    GuacUI.createChildElement(pan_overlay, "div", "indicator down");
    GuacUI.createChildElement(pan_overlay, "div", "indicator right");
    GuacUI.createChildElement(pan_overlay, "div", "indicator left");

    this.show = function() {
        document.body.appendChild(pan_overlay);
    };

    this.hide = function() {
        document.body.removeChild(pan_overlay);
    };

    /*
     * Transition to PAN_TYPING when the user taps on the overlay.
     */

    pan_overlay.addEventListener("click", function(e) {
        GuacUI.StateManager.setState(GuacUI.Client.states.PAN_TYPING);
        e.stopPropagation();
    }, true);

};

GuacUI.Client.PanOverlay.prototype = new GuacUI.Component();

/*
 * Show the pan overlay during PAN or PAN_TYPING modes.
 */

GuacUI.StateManager.registerComponent(
    new GuacUI.Client.PanOverlay(),
    GuacUI.Client.states.PAN,
    GuacUI.Client.states.PAN_TYPING
);

/**
 * Native Keyboard. This component uses a hidden textarea field to show the
 * platforms native on-screen keyboard (if any) or otherwise enable typing,
 * should the platform require a text field with focus for keyboard events to
 * register.
 * 
 * @constructor
 * @augments GuacUI.Component
 */
GuacUI.Client.NativeKeyboard = function() {

    /**
     * Event target. This is a hidden textarea element which will receive
     * key events.
     * @private
     */
    var eventTarget = GuacUI.createElement("textarea", "event-target");
    eventTarget.setAttribute("autocorrect", "off");
    eventTarget.setAttribute("autocapitalize", "off");

    this.show = function() {

        // Move to location of expected input
        eventTarget.style.left   = GuacUI.Client.expected_input_x + "px";
        eventTarget.style.top    = GuacUI.Client.expected_input_y + "px";
        eventTarget.style.width  = GuacUI.Client.expected_input_width + "px";
        eventTarget.style.height = GuacUI.Client.expected_input_height + "px";

        // Show and focus target
        document.body.appendChild(eventTarget);
        eventTarget.focus();

    };

    this.hide = function() {

        // Hide and blur target
        eventTarget.blur();
        document.body.removeChild(eventTarget);

    };

    /*
     * Automatically switch to INTERACTIVE mode after target loses focus
     */

    eventTarget.addEventListener("blur", function() {
        GuacUI.StateManager.setState(GuacUI.Client.states.INTERACTIVE);
    }, false);

};

GuacUI.Client.NativeKeyboard.prototype = new GuacUI.Component();

/*
 * Show native keyboard during PAN_TYPING mode only.
 */

GuacUI.StateManager.registerComponent(
    new GuacUI.Client.NativeKeyboard(),
    GuacUI.Client.states.PAN_TYPING
);

/**
 * On-screen Keyboard. This component provides a clickable/touchable keyboard
 * which sends key events to the Guacamole client.
 * 
 * @constructor
 * @augments GuacUI.Component
 */
GuacUI.Client.OnScreenKeyboard = function() {

    /**
     * Event target. This is a hidden textarea element which will receive
     * key events.
     * @private
     */
    var keyboard_container = GuacUI.createElement("div", "keyboard-container");

    var keyboard_resize_interval = null;

    // On-screen keyboard
    var keyboard = new Guacamole.OnScreenKeyboard("layouts/en-us-qwerty.xml");
    keyboard_container.appendChild(keyboard.getElement());

    var last_keyboard_width = 0;

    // Function for automatically updating keyboard size
    function updateKeyboardSize() {
        var currentSize = keyboard.getElement().offsetWidth;
        if (last_keyboard_width != currentSize) {
            keyboard.resize(currentSize);
            last_keyboard_width = currentSize;
        }
    }

    keyboard.onkeydown = function(keysym) {
        GuacUI.Client.client.sendKeyEvent(1, keysym);
    };

    keyboard.onkeyup = function(keysym) {
        GuacUI.Client.client.sendKeyEvent(0, keysym);
    };


    this.show = function() {

        // Show keyboard
        document.body.appendChild(keyboard_container);

        // Start periodic update of keyboard size
        keyboard_resize_interval = window.setInterval(
            updateKeyboardSize,
            GuacUI.Client.KEYBOARD_AUTO_RESIZE_INTERVAL);

        // Resize on window resize
        window.addEventListener("resize", updateKeyboardSize, true);

        // Initialize size
        updateKeyboardSize();

    };

    this.hide = function() {

        // Hide keyboard
        document.body.removeChild(keyboard_container);
        window.clearInterval(keyboard_resize_interval);
        window.removeEventListener("resize", updateKeyboardSize, true);

    };

};

GuacUI.Client.OnScreenKeyboard.prototype = new GuacUI.Component();

/*
 * Show on-screen keyboard during OSK mode only.
 */

GuacUI.StateManager.registerComponent(
    new GuacUI.Client.OnScreenKeyboard(),
    GuacUI.Client.states.OSK
);


/*
 * Set initial state
 */

GuacUI.StateManager.setState(GuacUI.Client.states.INTERACTIVE);

/**
 * Modal status display. Displays a message to the user, covering the entire
 * screen.
 * 
 * Normally, this should only be used when user interaction with other
 * components is impossible.
 * 
 * @constructor
 * @augments GuacUI.Component
 */
GuacUI.Client.ModalStatus = function(text) {

    // Create element hierarchy
    var outer  = GuacUI.createElement("div", "dialogOuter");
    var middle = GuacUI.createChildElement(outer, "div", "dialogMiddle");
    var dialog = GuacUI.createChildElement(middle, "div", "dialog");
    var status = GuacUI.createChildElement(dialog, "p", "status");

    // Set status text
    status.textContent = text;

    this.show = function() {
        document.body.appendChild(outer);
    };

    this.hide = function() {
        document.body.removeChild(outer);
    };

};

GuacUI.Client.ModalStatus.prototype = new GuacUI.Component();

