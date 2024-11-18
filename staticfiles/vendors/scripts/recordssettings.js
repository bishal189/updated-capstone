$(document).ready(function() {
    // Initialize DataTables
    var table = $('.checkbox-datatable').DataTable({
        'scrollCollapse': true,
        'autoWidth': false,
        'responsive': true,
        "lengthMenu": [[10, 25, 50, -1], [10, 25, 50, "All"]],
        "language": {
            "info": "_START_-_END_ of _TOTAL_ entries",
            searchPlaceholder: "Search",
            paginate: {
                next: '<i class="ion-chevron-right"></i>',
                previous: '<i class="ion-chevron-left"></i>'
            }
        },
        'columnDefs': [{
            'targets': 0,
            'searchable': false,
            'orderable': false,
            'className': 'dt-body-center',
            'render': function(data, type, full, meta) {
                return '<div class="dt-checkbox"><input type="checkbox" name="id[]" value="' + $('<div/>').text(data).html() + '"><span class="dt-checkbox-label"></span></div>';
            }
        }],
        'order': [[1, 'asc']]
    });

    // "Select All" checkbox functionality
    $('#example-select-all').on('click', function() {
        var rows = table.rows({ 'search': 'applied' }).nodes();
        $('input[type="checkbox"]', rows).prop('checked', this.checked);
    });

    // Handle individual checkbox changes
    $('.checkbox-datatable tbody').on('change', 'input[type="checkbox"]', function() {
        if (!this.checked) {
            var el = $('#example-select-all').get(0);
            if (el && el.checked && ('indeterminate' in el)) {
                el.indeterminate = true;
            }
        }
    });

    // Function to get selected rows
    function getSelectedRows(context) {
        context = context || $('.checkbox-datatable');
        var selectedCheckboxes = context.find('input[type="checkbox"]:not([name="select_all"]):checked');
        var selectedRows = selectedCheckboxes.closest('tr');
        return selectedRows;
    }

    // Check if at least one checkbox is selected
    function alertIfNoSelection() {
        var selectedRows = getSelectedRows();
        if (selectedRows.length === 0) {
            alert('Please select at least one entry.');
            return true;
        }
        return false;
    }
});

// added
// Handle the "Add" button click
document.getElementById('addButton').addEventListener('click', function() {
    const activeTab = document.querySelector('.nav-link.active').getAttribute('href');
    if (activeTab === '#child') {
        $('#childModal').modal('show');
    } else if (activeTab === '#pregnant') {
        $('#pregnantModal').modal('show');
    }
});

// Handle the "View" button click
document.getElementById('viewButton').addEventListener('click', function () {
    const activeTab = document.querySelector('.nav-link.active').getAttribute('href');
    const selectedRows = $(activeTab + ' .select-row:checked').closest('tr');

    if (selectedRows.length === 1) {
        const fields = ['name', 'gender', 'dateEntered', 'birthdate', 'ageInMonths', 'weight', 'height', 'status', 'fourPs'];
        const values = fields.map((field, index) => selectedRows.find('td').eq(index + 1).text());

        // Populate the modal with the selected record's details
        $('#viewName').text(values[0]);
        $('#viewGender').text(values[1]);
        $('#viewDateEntered').text(values[2]);
        $('#viewBirthdate').text(values[3]);
        $('#viewAgeInMonths').text(values[4]);
        $('#viewWeight').text(values[5]);
        $('#viewHeight').text(values[6]);
        $('#viewStatus').text(values[7]);
        $('#viewFourPs').text(values[8]);

        // Show the modal
        $('#viewModal').modal('show');
    } else {
        alert('Please select a single record to view.');
    }
});

// Printrecord
function printRecord() {
	const modalContent = document.querySelector('#viewModal .modal-body').innerHTML;
	const newWindow = window.open('', '_blank');
	newWindow.document.write(`
		<html>
		<head>
			<title>Print Record</title>
			<style>
				body {
					font-family: Arial, sans-serif;
					padding: 20px;
				}
				h2 {
					text-align: center;
					margin-bottom: 20px;
				}
				ul {
					list-style-type: none;
					padding: 0;
				}
				ul li {
					margin-bottom: 10px;
					padding: 10px;
					border-bottom: 1px solid #ccc;
				}
				ul li strong {
					display: inline-block;
					width: 150px;
				}
				ul li span {
					display: inline-block;
					width: calc(100% - 150px);
					text-align: left;
				}
				@media print {
					body {
						width: 80%;
						margin: auto;
					}
				}
			</style>
		</head>
		<body>
			<h2>Record Details</h2>
			${modalContent}
		</body>
		</html>
	`);
	newWindow.document.close();
	newWindow.print();
	newWindow.close();
}


// Calculate Age in Months
function calculateAgeInMonths(birthdate) {
    const birthDate = new Date(birthdate);
    const today = new Date();
    if (isNaN(birthDate.getTime()) || isNaN(today.getTime())) {
        return 'Invalid Date';
    }
    let months = (today.getFullYear() - birthDate.getFullYear()) * 12;
    months -= birthDate.getMonth();
    months += today.getMonth();
    if (today.getDate() < birthDate.getDate()) {
        months--;
    }
    return months;
}

// Update Child Age in Months
function updateChildAgeInMonths() {
    const birthdate = $('#childBirthdate').val();
    if (birthdate) {
        const ageInMonths = calculateAgeInMonths(birthdate);
        $('#childAgeInMonths').val(ageInMonths);
    }
}

// Update Pregnant Age in Months
function updatePregnantAgeInMonths() {
    const birthdate = $('#pregnantBirthdate').val();
    if (birthdate) {
        const ageInMonths = calculateAgeInMonths(birthdate);
        $('#pregnantAgeInMonths').val(ageInMonths);
    }
}

function getWeightStatus(weight) {
    // Define weight ranges for normal, underweight, and overweight
    const weightNum = parseFloat(weight.replace('kg', ''));
    if (weightNum < 10) { // Adjust the threshold as needed
        return 'underweight';
    } else if (weightNum >= 10 && weightNum <= 20) { // Adjust the threshold as needed
        return 'normal-weight';
    } else {
        return 'overweight';
    }
}

// Load Data from Local Storage
function loadData() {
    const childData = JSON.parse(localStorage.getItem('childData')) || [];
    const pregnantData = JSON.parse(localStorage.getItem('pregnantData')) || [];

    $('#child tbody').empty();
    $('#pregnant tbody').empty();

    childData.forEach(data => {
        const statusClass = getStatusClass(data.status);
        const newRow = `
            <tr>
                <td><input type="checkbox" class="select-row"></td>
                <td>${data.name}</td>
                <td>${data.gender}</td>
                <td>${data.dateEntered}</td>
                <td>${data.birthdate}</td>
                <td>${data.ageInMonths ? data.ageInMonths : 'N/A'}</td>
                <td>${data.weight}kg</td>
                <td>${data.height}cm</td>
                <td class="${statusClass}">${data.status}</td>
                <td>${data.fourPs}</td>
            </tr>
        `;
        $('#child tbody').append(newRow);
    });

    pregnantData.forEach(data => {
        const statusClass = getStatusClass(data.status);
        const newRow = `
            <tr>
                <td><input type="checkbox" class="select-row"></td>
                <td>${data.name}</td>
                <td>${data.gender}</td>
                <td>${data.dateEntered}</td>
                <td>${data.birthdate}</td>
                <td>${data.ageInMonths ? data.ageInMonths : 'N/A'}</td>
                <td>${data.weight}kg</td>
                <td>${data.height}cm</td>
                <td class="${statusClass}">${data.status}</td>
                <td>${data.fourPs}</td>
            </tr>
        `;
        $('#pregnant tbody').append(newRow);
    });
}

function getStatusClass(status) {
    switch (status) {
        case 'Normal':
            return 'status-normal';
        case 'Underweight':
            return 'status-underweight';
        case 'Overweight':
            return 'status-overweight';
        default:
            return '';
    }
}


// Save Data to Local Storage
function saveData() {
    const childData = [];
    $('#child tbody tr').each(function() {
        const row = $(this);
        childData.push({
            name: row.find('td').eq(1).text(),
            gender: row.find('td').eq(2).text(),
            dateEntered: row.find('td').eq(3).text(),
            birthdate: row.find('td').eq(4).text(),
            ageInMonths: row.find('td').eq(5).text(),
            weight: row.find('td').eq(6).text().replace('kg', ''),
            height: row.find('td').eq(7).text().replace('cm', ''),
            status: row.find('td').eq(8).text(),
            fourPs: row.find('td').eq(9).text()
        });
    });

    const pregnantData = [];
    $('#pregnant tbody tr').each(function() {
        const row = $(this);
        pregnantData.push({
            name: row.find('td').eq(1).text(),
            gender: row.find('td').eq(2).text(),
            dateEntered: row.find('td').eq(3).text(),
            birthdate: row.find('td').eq(4).text(),
            ageInMonths: row.find('td').eq(5).text(),
            weight: row.find('td').eq(6).text().replace('kg', ''),
            height: row.find('td').eq(7).text().replace('cm', ''),
            status: row.find('td').eq(8).text(),
            fourPs: row.find('td').eq(9).text()
        });
    });

    localStorage.setItem('childData', JSON.stringify(childData));
    localStorage.setItem('pregnantData', JSON.stringify(pregnantData));
}

let editingRow; // Variable to store the row being edited

// Add Child Form Submission
$('#submitChildForm').on('click', function(event) {
    event.preventDefault();

    if (editingRow) {
        // Update the existing row
        updateRow();
    } else {
        // Add a new row
        var name = $('#childName').val();
        var gender = $('#childGender').val();
        var birthdate = $('#childBirthdate').val();
        var weight = $('#childWeight').val();
        var height = $('#childHeight').val();
        var status = $('#childStatus').val();
        var ps = $('#child4ps').val();
        var ageInMonths = $('#childAgeInMonths').val();
        var statusClass = getStatusClass(status);

        var newRow = `
            <tr>
                <td><input type="checkbox" class="select-row"></td>
                <td>${name}</td>
                <td>${gender}</td>
                <td>${new Date().toISOString().split('T')[0]}</td>
                <td>${birthdate}</td>
                <td>${ageInMonths ? ageInMonths : 'N/A'}</td>
                <td>${weight}kg</td>
                <td>${height}cm</td>
                <td class="${statusClass}">${status}</td>
                <td>${ps}</td>
            </tr>
        `;

        $('#child tbody').append(newRow);
        saveData();
    }

    $('#childModal').modal('hide');
    $('#childForm')[0].reset();
    editingRow = null; // Reset the editing row
});

// Add Pregnant Form Submission
$('#submitPregnantForm').on('click', function(event) {
    event.preventDefault();

    if (editingRow) {
        // Update the existing row
        updateRow();
    } else {
        // Add a new row
        var name = $('#pregnantName').val();
        var gender = $('#pregnantGender').val();
        var birthdate = $('#pregnantBirthdate').val();
        var weight = $('#pregnantWeight').val();
        var height = $('#pregnantHeight').val();
        var status = $('#pregnantStatus').val();
        var ps = $('#pregnant4ps').val();
        var ageInMonths = $('#pregnantAgeInMonths').val();
        var statusClass = getStatusClass(status);

        var newRow = `
            <tr>
                <td><input type="checkbox" class="select-row"></td>
                <td>${name}</td>
                <td>${gender}</td>
                <td>${new Date().toISOString().split('T')[0]}</td>
                <td>${birthdate}</td>
                <td>${ageInMonths ? ageInMonths : 'N/A'}</td>
                <td>${weight}kg</td>
                <td>${height}cm</td>
                <td class="${statusClass}">${status}</td>
                <td>${ps}</td>
            </tr>
        `;

        $('#pregnant tbody').append(newRow);
        location.reload(); // Reload the entire page

        saveData();
    }

    $('#pregnantModal').modal('hide');
    $('#pregnantForm')[0].reset();
    editingRow = null; // Reset the editing row
});


// Edit Button Functionality
$('#editButton').on('click', function() {
    const activeTab = document.querySelector('.nav-link.active').getAttribute('href');
    const selectedRows = $(activeTab + ' .select-row:checked').closest('tr');

    if (selectedRows.length === 1) {
        editingRow = selectedRows.first(); // Store reference to the row being edited

        const fields = ['name', 'gender', 'birthdate', 'weight', 'height', 'status', 'fourPs'];
        const values = fields.map((field, index) => editingRow.find('td').eq(index + 1).text());

        if (activeTab === '#child') {
            $('#childName').val(values[0]);
            $('#childGender').val(values[1]);
            $('#childBirthdate').val(values[2]);
            $('#childWeight').val(values[3].replace('kg', ''));
            $('#childHeight').val(values[4].replace('cm', ''));
            $('#childStatus').val(values[5]);
            $('#child4ps').val(values[6]);
            $('#childModal').modal('show');
        } else if (activeTab === '#pregnant') {
            $('#pregnantName').val(values[0]);
            $('#pregnantGender').val(values[1]);
            $('#pregnantBirthdate').val(values[2]);
            $('#pregnantWeight').val(values[3].replace('kg', ''));
            $('#pregnantHeight').val(values[4].replace('cm', ''));
            $('#pregnantStatus').val(values[5]);
            $('#pregnant4ps').val(values[6]);
            $('#pregnantModal').modal('show');
        }
    } else {
        alert('Please select a single record to edit.');
    }
});

// Update Row Functionality
function updateRow() {
    if (editingRow) {
        const activeTab = document.querySelector('.nav-link.active').getAttribute('href');

        const updatedValues = {
            name: $('#' + (activeTab === '#child' ? 'childName' : 'pregnantName')).val(),
            gender: $('#' + (activeTab === '#child' ? 'childGender' : 'pregnantGender')).val(),
            birthdate: $('#' + (activeTab === '#child' ? 'childBirthdate' : 'pregnantBirthdate')).val(),
            weight: $('#' + (activeTab === '#child' ? 'childWeight' : 'pregnantWeight')).val() + 'kg',
            height: $('#' + (activeTab === '#child' ? 'childHeight' : 'pregnantHeight')).val() + 'cm',
            status: $('#' + (activeTab === '#child' ? 'childStatus' : 'pregnantStatus')).val(),
            fourPs: $('#' + (activeTab === '#child' ? 'child4ps' : 'pregnant4ps')).val()
        };

        // Calculate age in months for the updated row
        const ageInMonths = calculateAgeInMonths(updatedValues.birthdate);

        // Update the row with the new values
        editingRow.find('td').eq(1).text(updatedValues.name);
        editingRow.find('td').eq(2).text(updatedValues.gender);
        editingRow.find('td').eq(3).text(new Date().toISOString().split('T')[0]);
        editingRow.find('td').eq(4).text(updatedValues.birthdate);
        editingRow.find('td').eq(5).text(ageInMonths ? ageInMonths : 'N/A');
        editingRow.find('td').eq(6).text(updatedValues.weight);
        editingRow.find('td').eq(7).text(updatedValues.height);
        editingRow.find('td').eq(8).text(updatedValues.status);
        editingRow.find('td').eq(9).text(updatedValues.fourPs);

        editingRow = null; // Clear the row reference after updating
        saveData();
    } else {
        alert('No row selected for editing.');
    }
}


// Bind updateRow function to form submission
$('#submitChildFormEdit').on('click', function(event) {
    event.preventDefault();
    updateRow();
});

$('#submitPregnantFormEdit').on('click', function(event) {
    event.preventDefault();
    updateRow();
});

// Delete Button Functionality
$('#deleteButton').on('click', function() {
    const activeTab = document.querySelector('.nav-link.active').getAttribute('href');
    const selectedRows = $(activeTab + ' .select-row:checked').closest('tr');

    if (selectedRows.length === 0) {
        alert('Please select rows to delete.');
        return;
    }

    if (confirm('Are you sure you want to delete the selected records?')) {
        selectedRows.remove();
        saveData(); // Save the changes to local storage
    }
});

// Update Age in Months on Change
$('#childBirthdate').on('change', updateChildAgeInMonths);
$('#pregnantBirthdate').on('change', updatePregnantAgeInMonths);

$(document).ready(function() {
    loadData();

    // Initialize DataTable for Child and Pregnant tables
    $('#child table').DataTable({
        "pageLength": 10, // Show 10 entries per page
        "lengthChange": false // Disable the option to change the number of entries per page
    });

    $('#pregnant table').DataTable({
        "pageLength": 10, // Show 10 entries per page
        "lengthChange": false // Disable the option to change the number of entries per page
    });

    // Load saved data from Local Storage
    loadData();
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