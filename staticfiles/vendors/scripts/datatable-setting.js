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

    // Print button functionality
    $('#print-btn').on('click', function() {
        if (alertIfNoSelection()) return;

        // Identify the active tab
        var activeTab = $('.tabs .tab-content .active');
        var table = activeTab.find('.checkbox-datatable');

        // Debugging: Check if table contains expected columns
        console.log('Table Columns:', table.find('thead th').map(function() { return $(this).text(); }).get());

        // Get selected rows from the active tab
        var selectedRows = getSelectedRows.call({ selector: table });

        if (selectedRows.length === 0) {
            alert('No rows selected in the active tab.');
            return;
        }

        // Create a new window for printing
        var printWindow = window.open('', '', 'height=600,width=800');
        printWindow.document.write('<html><head><title>Print Report</title>');
        printWindow.document.write('</head><body>');
        printWindow.document.write('<h1>Print Report</h1>');
        printWindow.document.write('<table border="1">');

        // Add table headers
        printWindow.document.write('<thead><tr>');
        table.find('thead th').each(function() {
            printWindow.document.write('<th>' + $(this).text() + '</th>');
        });
        printWindow.document.write('</tr></thead><tbody>');

        // Add selected rows
        selectedRows.each(function() {
            var row = $(this);
            printWindow.document.write('<tr>');
            row.find('td').each(function() {
                printWindow.document.write('<td>' + $(this).text() + '</td>');
            });
            printWindow.document.write('</tr>');
        });

        printWindow.document.write('</tbody></table>');
        printWindow.document.write('</body></html>');
        printWindow.document.close();
        printWindow.print();
    });

    // View button functionality
    $('#view-btn').on('click', function() {
        if (alertIfNoSelection()) return;

        var selectedRows = getSelectedRows();
        selectedRows.each(function() {
            var row = $(this);
            var data = [];
            row.find('td').each(function() {
                data.push($(this).text());
            });
            alert('View Details: \n' + data.join(', '));
        });
    });

    // Edit button functionality
    $('#edit-btn').on('click', function() {
        if (alertIfNoSelection()) return;

        var selectedRows = getSelectedRows();
        selectedRows.each(function() {
            var row = $(this);
            var data = [];
            row.find('td').each(function() {
                data.push($(this).text());
            });
            alert('Edit Details: \n' + data.join(', '));
        });
    });

    // Archive button functionality
    $('#archive-btn').on('click', function() {
        if (alertIfNoSelection()) return;

        var selectedRows = getSelectedRows();
        selectedRows.each(function() {
            var row = $(this);
            var data = [];
            row.find('td').each(function() {
                data.push($(this).text());
            });
            alert('Archive Details: \n' + data.join(', '));
            // Here you might want to send a request to your server to archive the data
        });
    });

});
