jQuery(document).ready(function() {
    var currentEvent; // Variable to store the currently edited event
    var today = moment().startOf('day'); // Today's date at midnight

    // Load events from local storage
    var savedEvents = JSON.parse(localStorage.getItem('calendarEvents')) || [];

    // Initialize the calendar
    jQuery('#calendar').fullCalendar({
        themeSystem: 'bootstrap4',
        editable: true,
        droppable: true,
        header: {
            left: 'title',
            center: 'month,agendaWeek,agendaDay',
            right: 'today prev,next'
        },
        events: savedEvents,
        dayClick: function(date) {
            if (date.isBefore(today)) {
                alert("You cannot add an event in the past.");
                return;
            }
            jQuery('#modal-view-event-add').modal('show');
            jQuery('#add-event-form #event-start').val(date.format("YYYY-MM-DDTHH:mm:ss"));
            jQuery('#add-event-form #event-end').val(date.format("YYYY-MM-DDTHH:mm:ss"));
        },
        eventClick: function(event) {
            currentEvent = event; // Store the clicked event

            var modal = jQuery('#modal-view-event');
            modal.find('.modal-title').text(event.title);
            modal.find('.modal-body').html(`
                <p><strong>Title:</strong> ${event.title}</p>
                <p><strong>Description:</strong> ${event.description}</p>
                <p><strong>Start Date:</strong> ${moment(event.start).format("MMMM Do YYYY, h:mm a")}</p>
                <p><strong>End Date:</strong> ${event.end ? moment(event.end).format("MMMM Do YYYY, h:mm a") : 'N/A'}</p>
            `);
            modal.find('.modal-footer').html(`
                <button type="button" class="btn btn-primary edit-event">Edit</button>
                <button type="button" class="btn btn-danger delete-event">Delete</button>
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            `);
            modal.modal('show');

            modal.find('.edit-event').off('click').on('click', function() {
                jQuery('#edit-event-id').val(event._id);
                jQuery('#edit-event-title').val(event.title);
                jQuery('#edit-event-description').val(event.description);
                jQuery('#edit-event-start').val(moment(event.start).format("YYYY-MM-DDTHH:mm:ss"));
                jQuery('#edit-event-end').val(event.end ? moment(event.end).format("YYYY-MM-DDTHH:mm:ss") : '');
                jQuery('#modal-view-event').modal('hide');
                jQuery('#modal-edit-event').modal('show');
            });

            // Delete event
            modal.find('.delete-event').off('click').on('click', function() {
                jQuery('#calendar').fullCalendar('removeEvents', event._id);
                saveEventsToLocalStorage();
                jQuery('#modal-view-event').modal('hide');
            });
        },
        eventDrop: function(event, delta, revertFunc) {
            if (event.start.isBefore(today)) {
                alert("You cannot move an event to a past date.");
                revertFunc(); // Revert the drag operation
            } else {
                currentEvent = event;
                saveEventsToLocalStorage(); // Save after moving the event
            }
        },
        eventResize: function(event, delta, revertFunc) {
            if (event.start.isBefore(today)) {
                alert("You cannot resize an event to start before today.");
                revertFunc(); // Revert the resize operation
            } else {
                currentEvent = event;
                saveEventsToLocalStorage(); // Save after resizing the event
            }
        }
    });

    // Add event form submission
    jQuery("#add-event-form").submit(function(e) {
        e.preventDefault();
        var eventStart = moment(jQuery("#event-start").val());
        var eventEnd = moment(jQuery("#event-end").val());

        if (eventStart.isBefore(today)) {
            alert("You cannot add an event in the past.");
            return;
        }
        if (eventEnd.isBefore(eventStart)) {
            alert("The end date cannot be before the start date.");
            return;
        }

        var eventData = {
            id: Date.now(), // Unique ID for each event
            title: jQuery("#event-title").val(),
            description: jQuery("#event-description").val(),
            start: jQuery("#event-start").val(),
            end: jQuery("#event-end").val(),
            className: 'fc-bg-default',
            icon: 'calendar'
        };
        jQuery('#calendar').fullCalendar('renderEvent', eventData, true);
        saveEventsToLocalStorage();
        jQuery('#modal-view-event-add').modal('hide');
        jQuery('#add-event-form')[0].reset(); // Reset the form after submission
    });

    // Edit event form submission
    jQuery("#edit-event-form").submit(function(e) {
        e.preventDefault();
        if (currentEvent) {
            var eventStart = moment(jQuery("#edit-event-start").val());
            var eventEnd = moment(jQuery("#edit-event-end").val());

            if (eventStart.isBefore(today)) {
                alert("You cannot edit an event to start in the past.");
                return;
            }
            if (eventEnd.isBefore(eventStart)) {
                alert("The end date cannot be before the start date.");
                return;
            }

            currentEvent.title = jQuery("#edit-event-title").val();
            currentEvent.description = jQuery("#edit-event-description").val();
            currentEvent.start = jQuery("#edit-event-start").val();
            currentEvent.end = jQuery("#edit-event-end").val();
            jQuery('#calendar').fullCalendar('updateEvent', currentEvent);
            saveEventsToLocalStorage();
            jQuery('#modal-edit-event').modal('hide');
        }
    });

    // Function to save events to local storage
    function saveEventsToLocalStorage() {
        var events = jQuery('#calendar').fullCalendar('clientEvents');
        var eventsToSave = events.map(function(event) {
            return {
                id: event.id,
                title: event.title,
                description: event.description,
                start: event.start.format(),
                end: event.end ? event.end.format() : null,
                className: event.className,
                icon: event.icon
            };
        });
        localStorage.setItem('calendarEvents', JSON.stringify(eventsToSave));
    }
});

document.addEventListener('DOMContentLoaded', function() {
    // Load profile name and image from local storage
    const profileName = localStorage.getItem('profileName');
    const profileImage = localStorage.getItem('profileImage');

    console.log('Loaded profile name:', profileName); // Debugging log
    console.log('Loaded profile image:', profileImage); // Debugging log

    // Update the dropdown with the stored profile data
    if (profileName) {
        document.getElementById('dropdown-profile-name').textContent = profileName;
    }

    if (profileImage) {
        document.getElementById('dropdown-profile-picture').src = profileImage;
    }
});