$(document).ready(function () {
    var checkboxTable = $('.checkbox-datatable').DataTable({
        scrollCollapse: true,
        autoWidth: false,
        responsive: true,
        lengthMenu: [[10, 25, 50, -1], [10, 25, 50, "All"]],
        language: {
            info: "_START_-_END_ of _TOTAL_ entries",
            searchPlaceholder: "Search",
            paginate: {
                next: '<i class="ion-chevron-right"></i>',
                previous: '<i class="ion-chevron-left"></i>'
            }
        },
        columnDefs: [{
            targets: 0,
            searchable: false,
            orderable: false,
            className: 'dt-body-center',
            render: function (data, type, full, meta) {
                return '<div class="dt-checkbox"><input type="checkbox" name="id[]" value=""><span class="dt-checkbox-label"></span></div>';
            }
        }],
        order: [[1, 'asc']]
    });

    function loadData() {
        $.ajax({
            url: '/admin_maternal_record/load',
            method: 'GET',
            success: function (response) {
                response.forEach(row => {
                    const addedRow = checkboxTable.row.add(row).draw();
                    $(addedRow.node()).data('image', row[9]);
                });
            },
            error: function (error) {
                console.error("Error loading data:", error);
            }
        });
    }

    loadData();

    function saveData() {
        const dataToSave = [];
        checkboxTable.rows().every(function () {
            const rowData = this.data();
            const rowNode = this.node();
            rowData[9] = $(rowNode).data('image') || '';
            dataToSave.push(rowData);
        });

        $.ajax({
            url: '/admin_maternal_record/save',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(dataToSave),
            success: function (response) {
                console.log("Data saved successfully:", response);
            },
            error: function (error) {
                console.error("Error saving data:", error);
            }
        });
    }

    var isEditMode = false;
    var currentRowNode = null;

    $('#viewButton').on('click', function () {
        var selectedRows = getSelectedRows();

        if (selectedRows.length !== 1) {
            alert("Please select only one row to view.");
            return;
        }

        var data = selectedRows[0];
        var rowNode = checkboxTable.row(function (idx, data, node) {
            return $('input[type="checkbox"]', node).is(':checked');
        }).node();

        var imageUrl = $(rowNode).data('image');
        if (imageUrl) {
            $('#viewImage').attr('src', imageUrl).css({
                'max-width': '100%',
                'max-height': '150px',
                'object-fit': 'contain',
                'display': 'block',
                'margin': '0 auto'
            }).show();
        } else {
            $('#viewImage').hide();
        }

        $('#viewName').text(data[1]);
        $('#viewStatus').text(data[2]);
        $('#viewDateEntered').text(data[3]);
        $('#viewBirthday').text(data[4]);
        $('#viewAge').text(data[5]);
        $('#viewMUAC').text(data[6]);
        $('#viewNutritionalStatus').text(data[7]);
        $('#viewFourPsMember').text(data[8]);

        $('#viewEntryModal').modal('show');
    });

    function getSelectedRows() {
        return checkboxTable.rows(function (idx, data, node) {
            return $('input[type="checkbox"]', node).is(':checked');
        }).data();
    }

    $('#editButton').on('click', function () {
        var selectedRows = getSelectedRows();

        if (selectedRows.length !== 1) {
            alert("Please select only one row to edit.");
            return;
        }

        isEditMode = true;
        var data = selectedRows[0];
        currentRowNode = checkboxTable.row(function (idx, data, node) {
            return $('input[type="checkbox"]', node).is(':checked');
        }).node();

        // Split the name into first, middle, and last names
        var fullName = data[1].split(" ");
        var firstName = fullName[0];
        var middleName = fullName.length > 2 ? fullName.slice(1, fullName.length - 1).join(" ") : '';
        var lastName = fullName.length > 1 ? fullName[fullName.length - 1] : '';

        $('#first_name').val(firstName);
        $('#middle_name').val(middleName);
        $('#last_name').val(lastName);
        $('#status').val(data[2]);
        $('#birthday').val(data[4]);
        $('#age').val(data[5]);
        $('#muac').val(data[6]);
        $('#nutritional-status').val(data[7]);
        $('#4ps-member').val(data[8]);

        $('#imagePreview').attr('src', $(currentRowNode).data('image')).show();

        $('#addModal').modal('show');
    });

    $('#addButton').on('click', function () {
        var selectedRows = getSelectedRows();

        if (selectedRows.length > 0) {
            return;
        }

        isEditMode = false;
        $('#addForm')[0].reset();
        $('#imagePreview').hide();
        $('#addModal').modal('show');
    });

    function checkCheckboxes() {
        var selectedRows = getSelectedRows();
        $('#addButton').prop('disabled', selectedRows.length > 0);
    }

    $('.checkbox-datatable tbody').on('change', 'input[type="checkbox"]', function () {
        checkCheckboxes();
    });

    $('#addForm').on('submit', function (e) {
        e.preventDefault();

        const imageUrl = $('#imagePreview').attr('src') || '';

        const newRow = [
            '<div class="dt-checkbox"><input type="checkbox" name="id[]" value=""><span class="dt-checkbox-label"></span></div>',
            `${$('#first_name').val()} ${$('#middle_name').val()} ${$('#last_name').val()}`.trim(),
            $('#status').val(),
            new Date().toLocaleDateString(),
            $('#birthday').val(),
            $('#age').val(),
            $('#muac').val(),
            $('#nutritional-status').val(),
            $('#4ps-member').val(),
            imageUrl
        ];

        if (isEditMode) {
            $.ajax({
                url: '/admin_maternal_record/update',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ row: newRow, id: currentRowNode.id }),
                success: function (response) {
                    checkboxTable.row(currentRowNode).data(newRow).draw();
                    $(currentRowNode).data('image', imageUrl);
                    $('#addModal').modal('hide');
                },
                error: function (error) {
                    console.error("Error updating data:", error);
                }
            });
        } else {
            $.ajax({
                url: '/admin_maternal_record/add',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(newRow),
                success: function (response) {
                    const addedRow = checkboxTable.row.add(newRow).draw();
                    $(addedRow.node()).data('image', imageUrl);
                    $('#addModal').modal('hide');
                },
                error: function (error) {
                    console.error("Error adding data:", error);
                }
            });
        }
    });

    $('#deleteButton').on('click', function () {
        var selectedRows = checkboxTable.rows(function (idx, data, node) {
            return $('input[type="checkbox"]', node).is(':checked');
        });

        if (selectedRows.data().length === 0) {
            alert("Please select a row to delete.");
            return;
        }

        if (confirm("Are you sure you want to delete the selected row(s)?")) {
            selectedRows.remove().draw();
            saveData();
        }
    });

    $('#example-select-all').on('click', function () {
        var rows = checkboxTable.rows({ 'search': 'applied' }).nodes();
        $('input[type="checkbox"]', rows).prop('checked', this.checked);
    });
});
