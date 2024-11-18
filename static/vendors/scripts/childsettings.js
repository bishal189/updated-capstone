$(document).ready(function () {
  var table = $(".checkbox-datatable").DataTable({
    scrollX: true,
    scrollCollapse: true,
    autoWidth: false,
    responsive: false,
    lengthMenu: [
      [10, 25, 50, -1],
      [10, 25, 50, "All"],
    ],
    language: {
      info: "START_-_END of TOTAL entries",
      searchPlaceholder: "Search",
      paginate: {
        next: '<i class="ion-chevron-right"></i>',
        previous: '<i class="ion-chevron-left"></i>',
      },
      emptyTable: "No data available in table",
    },
    columnDefs: [
      {
        targets: 0,
        searchable: false,
        orderable: false,
        className: "dt-body-center",
        render: function (data, type, full, meta) {
          return (
            '<div class="dt-checkbox"><input type="checkbox" name="id[]" value="' +
            $("<div/>").text(data).html() +
            '"><span class="dt-checkbox-label"></span></div>'
          );
        },
      },
    ],
    order: [[1, "asc"]],
  });

  var isEditing = false;
  var currentRowNode = null;

  $("#example-select-all").on("click", function () {
    var rows = table.rows({ search: "applied" }).nodes();
    $('input[type="checkbox"]', rows).prop("checked", this.checked);
  });

  $(".checkbox-datatable tbody").on(
    "change",
    'input[type="checkbox"]',
    function () {
      if (!this.checked) {
        var el = $("#example-select-all").get(0);
        if (el && el.checked && "indeterminate" in el) {
          el.indeterminate = true;
        }
      }
    }
  );

  $("#addButton").on("click", function () {
    $("#addEntryForm")[0].reset();
    $("#date_entered").val(new Date().toISOString().split("T")[0]);
    $("#imagePreview").hide();
    $("#child_image").val("");
    isEditing = false;
    $("#addEntryModal").modal("show");
  });

  $("#birthday").on("change", function () {
    var birthday = new Date($(this).val());
    var age_in_months = calculateAgeInMonths(birthday);
    $("#age_in_months").val(age_in_months);
  });

  function calculateAgeInMonths(birthday) {
    var today = new Date();
    var years = today.getFullYear() - birthday.getFullYear();
    var months = today.getMonth() - birthday.getMonth();

    if (months < 0) {
      years--;
      months += 12;
    }

    return years * 12 + months;
  }

  $("#child_image").on("change", function (event) {
    var reader = new FileReader();
    reader.onload = function (e) {
      $("#imagePreview").attr("src", e.target.result).show();
    };
    reader.readAsDataURL(event.target.files[0]);
  });

  const growthStandards = {
    Male: {
      0: {
        weight: {
          N: [2.5, 3.2],
          UW: [2.2, 2.4],
          SU: [0, 2.1],
          OW: [3.3, 4.2],
        },
        height: {
          N: [46.1, 51.7],
          ST: [0, 46.0],
          T: [51.8, 55.5],
        },
      },
      1: {
        weight: {
          N: [3.4, 4.4],
          UW: [3.0, 3.3],
          SU: [0, 2.9],
          OW: [4.5, 5.8],
        },
        height: {
          N: [50.0, 55.6],
          ST: [0, 49.9],
          T: [55.7, 59.6],
        },
      },
      2: {
        weight: {
          N: [4.3, 5.4],
          UW: [3.7, 4.2],
          SU: [0, 3.6],
          OW: [5.5, 7.1],
        },
        height: {
          N: [53.1, 58.4],
          ST: [0, 53.0],
          T: [58.5, 62.4],
        },
      },
      3: {
        weight: {
          N: [5.0, 6.3],
          UW: [4.4, 4.9],
          SU: [0, 4.3],
          OW: [6.4, 8.0],
        },
        height: {
          N: [55.6, 61.0],
          ST: [0, 55.5],
          T: [61.1, 65.0],
        },
      },
      4: {
        weight: {
          N: [5.6, 7.0],
          UW: [5.0, 5.5],
          SU: [0, 4.9],
          OW: [7.1, 8.7],
        },
        height: {
          N: [57.8, 63.3],
          ST: [0, 57.7],
          T: [63.4, 67.3],
        },
      },
      5: {
        weight: {
          N: [6.1, 7.5],
          UW: [5.5, 6.0],
          SU: [0, 5.4],
          OW: [7.6, 9.3],
        },
        height: {
          N: [59.6, 65.3],
          ST: [0, 59.5],
          T: [65.4, 69.4],
        },
      },
      6: {
        weight: {
          N: [6.4, 7.9],
          UW: [5.8, 6.3],
          SU: [0, 5.7],
          OW: [8.0, 9.8],
        },
        height: {
          N: [61.2, 67.1],
          ST: [0, 61.1],
          T: [67.2, 71.3],
        },
      },
      7: {
        weight: {
          N: [6.7, 8.3],
          UW: [6.1, 6.6],
          SU: [0, 6.0],
          OW: [8.4, 10.3],
        },
        height: {
          N: [62.7, 68.7],
          ST: [0, 62.6],
          T: [68.8, 73.0],
        },
      },
      8: {
        weight: {
          N: [7.0, 8.6],
          UW: [6.3, 6.9],
          SU: [0, 6.2],
          OW: [8.7, 10.7],
        },
        height: {
          N: [64.0, 70.1],
          ST: [0, 63.9],
          T: [70.2, 74.5],
        },
      },
      9: {
        weight: {
          N: [7.2, 8.9],
          UW: [6.5, 7.1],
          SU: [0, 6.4],
          OW: [9.0, 11.0],
        },
        height: {
          N: [65.3, 71.5],
          ST: [0, 65.2],
          T: [71.6, 75.9],
        },
      },
      10: {
        weight: {
          N: [7.5, 9.2],
          UW: [6.7, 7.4],
          SU: [0, 6.6],
          OW: [9.3, 11.4],
        },
        height: {
          N: [66.5, 72.8],
          ST: [0, 66.4],
          T: [72.9, 77.2],
        },
      },
      11: {
        weight: {
          N: [7.7, 9.9],
          UW: [6.8, 7.6],
          SU: [0, 6.7],
          OW: [10.0, 13.0],
        },
        height: {
          N: [69.1, 75.2],
          ST: [0, 69.0],
          T: [75.3, 78.5],
        },
      },
      12: {
        weight: {
          N: [7.9, 10.2],
          UW: [7.0, 7.8],
          SU: [0, 6.8],
          OW: [10.3, 13.1],
        },
        height: {
          N: [70.1, 76.4],
          ST: [0, 70.0],
          T: [76.5, 80.0],
        },
      },
      13: {
        weight: {
          N: [8.1, 10.5],
          UW: [7.1, 8.0],
          SU: [0, 7.0],
          OW: [10.6, 13.4],
        },
        height: {
          N: [71.3, 77.5],
          ST: [0, 71.2],
          T: [77.6, 81.0],
        },
      },
      14: {
        weight: {
          N: [8.3, 10.7],
          UW: [7.2, 8.2],
          SU: [0, 7.1],
          OW: [10.8, 13.7],
        },
        height: {
          N: [72.5, 78.6],
          ST: [0, 72.4],
          T: [78.7, 82.0],
        },
      },
      15: {
        weight: {
          N: [8.5, 10.9],
          UW: [7.4, 8.4],
          SU: [0, 7.3],
          OW: [11.0, 14.0],
        },
        height: {
          N: [73.6, 79.8],
          ST: [0, 73.5],
          T: [79.9, 83.2],
        },
      },
      16: {
        weight: {
          N: [8.7, 11.2],
          UW: [7.5, 8.6],
          SU: [0, 7.4],
          OW: [11.3, 14.3],
        },
        height: {
          N: [74.6, 80.8],
          ST: [0, 74.5],
          T: [80.9, 84.3],
        },
      },
      17: {
        weight: {
          N: [8.9, 11.4],
          UW: [7.7, 8.8],
          SU: [0, 7.6],
          OW: [11.5, 14.6],
        },
        height: {
          N: [75.6, 81.8],
          ST: [0, 75.5],
          T: [81.9, 85.4],
        },
      },
      18: {
        weight: {
          N: [9.1, 11.6],
          UW: [7.8, 9.0],
          SU: [0, 7.7],
          OW: [11.7, 14.8],
        },
        height: {
          N: [76.6, 82.8],
          ST: [0, 76.5],
          T: [82.9, 86.5],
        },
      },
      19: {
        weight: {
          N: [9.2, 11.8],
          UW: [8.0, 9.1],
          SU: [0, 7.9],
          OW: [11.9, 15.1],
        },
        height: {
          N: [77.5, 83.8],
          ST: [0, 77.4],
          T: [83.9, 87.6],
        },
      },
      20: {
        weight: {
          N: [9.4, 12.1],
          UW: [8.1, 9.3],
          SU: [0, 8.0],
          OW: [12.2, 15.4],
        },
        height: {
          N: [78.5, 84.7],
          ST: [0, 78.4],
          T: [84.8, 88.6],
        },
      },
      21: {
        weight: {
          N: [9.6, 12.3],
          UW: [8.3, 9.5],
          SU: [0, 8.2],
          OW: [12.4, 15.6],
        },
        height: {
          N: [79.4, 85.6],
          ST: [0, 79.3],
          T: [85.7, 89.6],
        },
      },
      22: {
        weight: {
          N: [9.8, 12.5],
          UW: [8.4, 9.7],
          SU: [0, 8.3],
          OW: [12.6, 15.9],
        },
        height: {
          N: [80.3, 86.5],
          ST: [0, 80.2],
          T: [86.6, 90.5],
        },
      },
      23: {
        weight: {
          N: [10.0, 12.7],
          UW: [8.6, 9.8],
          SU: [0, 8.5],
          OW: [12.8, 16.1],
        },
        height: {
          N: [81.1, 87.3],
          ST: [0, 81.0],
          T: [87.4, 91.4],
        },
      },
      24: {
        weight: {
          N: [10.2, 12.9],
          UW: [8.7, 10.0],
          SU: [0, 8.6],
          OW: [13.0, 16.4],
        },
        height: {
          N: [82.0, 88.2],
          ST: [0, 81.9],
          T: [88.3, 92.3],
        },
      },
      25: {
        weight: {
          N: [10.3, 13.1],
          UW: [8.9, 10.2],
          SU: [0, 8.8],
          OW: [13.2, 16.6],
        },
        height: {
          N: [82.8, 89.0],
          ST: [0, 82.7],
          T: [89.1, 93.2],
        },
      },
      26: {
        weight: {
          N: [10.5, 13.3],
          UW: [9.0, 10.3],
          SU: [0, 8.9],
          OW: [13.4, 16.9],
        },
        height: {
          N: [83.7, 89.8],
          ST: [0, 83.6],
          T: [89.9, 94.0],
        },
      },
      27: {
        weight: {
          N: [10.7, 13.5],
          UW: [9.2, 10.5],
          SU: [0, 9.1],
          OW: [13.6, 17.1],
        },
        height: {
          N: [84.5, 90.7],
          ST: [0, 84.4],
          T: [90.8, 94.9],
        },
      },
      28: {
        weight: {
          N: [10.8, 13.7],
          UW: [9.3, 10.7],
          SU: [0, 9.2],
          OW: [13.8, 17.4],
        },
        height: {
          N: [85.3, 91.5],
          ST: [0, 85.2],
          T: [91.6, 95.7],
        },
      },
      29: {
        weight: {
          N: [11.0, 13.9],
          UW: [9.5, 10.8],
          SU: [0, 9.4],
          OW: [14.0, 17.6],
        },
        height: {
          N: [86.1, 92.2],
          ST: [0, 86.0],
          T: [92.3, 96.5],
        },
      },
      30: {
        weight: {
          N: [11.2, 14.1],
          UW: [9.6, 11.0],
          SU: [0, 9.5],
          OW: [14.2, 17.8],
        },
        height: {
          N: [86.9, 93.0],
          ST: [0, 86.8],
          T: [93.1, 97.3],
        },
      },
      31: {
        weight: {
          N: [11.3, 14.3],
          UW: [9.8, 11.1],
          SU: [0, 9.7],
          OW: [14.4, 18.1],
        },
        height: {
          N: [87.6, 93.8],
          ST: [0, 87.5],
          T: [93.9, 98.1],
        },
      },

      // Additional mappings for other ages
    },
    Female: {
      0: {
        weight: {
          N: [2.4, 3.2],
          UW: [2.0, 2.3],
          SU: [0, 1.9],
          OW: [3.3, 3.9],
        },
        height: {
          N: [45.6, 52.7],
          ST: [0, 45.5],
          T: [52.8, 57.2],
        },
      },
      1: {
        weight: {
          N: [3.2, 4.2],
          UW: [2.7, 3.1],
          SU: [0, 2.6],
          OW: [4.3, 5.0],
        },
        height: {
          N: [49.8, 57.6],
          ST: [0, 49.7],
          T: [57.7, 62.2],
        },
      },
      2: {
        weight: {
          N: [4.0, 5.4],
          UW: [3.5, 3.9],
          SU: [0, 3.4],
          OW: [5.5, 6.4],
        },
        height: {
          N: [53.0, 60.9],
          ST: [0, 52.9],
          T: [61.0, 66.5],
        },
      },
      3: {
        weight: {
          N: [4.7, 6.2],
          UW: [4.1, 4.6],
          SU: [0, 4.0],
          OW: [6.3, 7.2],
        },
        height: {
          N: [55.6, 63.8],
          ST: [0, 55.5],
          T: [63.9, 69.7],
        },
      },
      // Continue similarly for each month up to 30
      30: {
        weight: {
          N: [11.2, 14.1],
          UW: [9.6, 11.0],
          SU: [0, 9.5],
          OW: [14.2, 17.8],
        },
        height: {
          N: [86.9, 93.0],
          ST: [0, 86.8],
          T: [93.1, 97.3],
        },
      },
    },
  };

  // Function to get the category based on the value and range
  function getCategory(value, ranges) {
    for (const category in ranges) {
      const [min, max] = ranges[category];
      if (value >= min && value <= max) {
        return category;
      }
    }
    return "unknown"; // If no category matches
  }

  $("#height, #weight").change(function () {
    const age = parseInt(document.getElementById("age_in_months").value, 10); // Replace with dynamic value if available
    const gender = document.getElementById("gender").value; // Replace with dynamic value if available
    const weight = parseFloat(document.getElementById("weight").value);
    const height = parseFloat(document.getElementById("height").value);

    // Only run check if both weight and height are populated
    if (weight && height) {
      checkGrowth(age, gender, weight, height);
    }
  });

  // Function to get the category based on the value and range
  function getCategory(value, ranges) {
    for (const category in ranges) {
      const [min, max] = ranges[category];
      if (value >= min && value <= max) {
        return category;
      }
    }
    return "unknown"; // If no category matches
  }

  // Main function to compare inputs to standards
  function checkGrowth(age, gender, weight, height) {
    const standards = growthStandards[gender]?.[age];
    if (!standards) {
      console.log("No standards found for the specified age and gender.");
      return;
    }

    // Check weight and height categories
    const weightCategory = getCategory(weight, standards.weight);
    const heightCategory = getCategory(height, standards.height);

    // Display results or autofill fields
    console.log(`Weight category: ${weightCategory}`);
    console.log(`Height category: ${heightCategory}`);
    console.log(
      `Weight for LT/HT Status: ${weightCategory} / ${heightCategory}`
    );

    // Optional: Update the DOM or autofill values if needed
    document.getElementById("weight_for_age_status").value = weightCategory;
    document.getElementById("height_for_age_status").value = heightCategory;
    document.getElementById(
      "weight_for_lt_ht_status"
    ).value = `${weightCategory} / ${heightCategory}`;
  }

  function getWeightForAgeStatus(ageInMonths, weight, gender) {
    const standard = growthStandards[gender][ageInMonths]?.weight;
    if (standard) {
      if (weight <= standard.severelyUnderweight[1])
        return "Severely Underweight";
      if (weight <= standard.underweight[1]) return "UW";
      if (weight <= standard.normal[1]) return "N";
      if (weight >= standard.overweight[0]) return "OW";
    }
    return "Unknown";
  }

  function getHeightForAgeStatus(ageInMonths, height, gender) {
    const standard = growthStandards[gender][ageInMonths]?.height;
    if (standard) {
      if (height <= standard.stunted[1]) return "stunted";
      if (height <= standard.normal[1]) return "Normal";
      if (height >= standard.tall[0]) return "Tall";
    }
    return "Unknown";
  }

  $("#addEntryForm").on("submit", function (e) {
    e.preventDefault();
    alert("Form submitted");

    var formData = new FormData(this);
    var imageBase64 = $("#imagePreview").attr("src") || "";

    // Check if there's an image and append it to FormData
    if (imageBase64) {
      formData.append("imageBase64", imageBase64);
    }

    $.ajax({
      type: "POST",
      url: $(this).attr("action"),
      data: formData,
      contentType: false,
      processData: false,
      success: function (response) {
        addNewEntryToTable(response.newEntry);
        $("#addEntryModal").modal("hide");
        alert("Entry added successfully!");
      },
      error: function (xhr, status, error) {
        alert("An error occurred: " + xhr.responseText);
      },
    });
  });

  function addNewEntryToTable(entry) {
    const newRowData = [
      '<div class="dt-checkbox"><input type="checkbox" name="select" value="1"><span class="dt-checkbox-label"></span></div>',
      entry.name,
      entry.gender,
      entry.date_entered,
      entry.birthday,
      entry.age_in_months,
      entry.weight,
      entry.height,
      entry.weight_for_age_status,
      entry.height_for_age_status,
      entry.weight_for_lt_ht_status,
      entry.imageBase64,
    ];

    table.row.add(newRowData).draw();
  }

  $("#deleteButton").on("click", function () {
    var selectedRows = table
      .rows({ search: "applied" })
      .nodes()
      .to$()
      .filter(function () {
        return $(this).find('input[type="checkbox"]').is(":checked");
      });

    if (selectedRows.length === 0) {
      alert("Please select at least one row to delete.");
      return;
    }

    var confirmDelete = confirm(
      "Are you sure you want to delete the selected entry(s)?"
    );
    if (confirmDelete) {
      selectedRows.each(function () {
        table.row($(this)).remove();
      });
      table.draw();
      alert("Selected entry(s) have been deleted.");
    }
  });

  $("#editButton").on("click", function () {
    var selectedRows = table
      .rows({ search: "applied" })
      .nodes()
      .to$()
      .filter(function () {
        return $(this).find('input[type="checkbox"]').is(":checked");
      });

    if (selectedRows.length === 1) {
      currentRowNode = selectedRows[0];
      var rowData = table.row(currentRowNode).data();

      // Populate the modal with the selected row data
      $("#first_name").val(rowData[1].split(" ")[0]);
      $("#middle_name").val(rowData[1].split(" ").slice(1, -1).join(" "));
      $("#last_name").val(rowData[1].split(" ").slice(-1)[0]);
      $("#gender").val(rowData[2]);
      $("#date_entered").val(rowData[3]);
      $("#birthday").val(rowData[4]);
      $("#age_in_months").val(rowData[5]);
      $("#weight").val(rowData[6]);
      $("#height").val(rowData[7]);
      $("#weight_for_age_status").val(rowData[8]);
      $("#height_for_age_status").val(rowData[9]);
      $("#weight_for_lt_ht_status").val(rowData[10]);

      // Load image for editing
      if (rowData[11]) {
        $("#imagePreview").attr("src", rowData[11]).show();
      } else {
        $("#imagePreview").hide();
      }

      $("#addEntryModal").modal("show");
      isEditing = true;
    } else {
      alert("Please select exactly one row to edit.");
    }
  });

  function updateTableRow(rowNode, entry) {
    const updatedRowData = [
      '<div class="dt-checkbox"><input type="checkbox" name="select" value="1"><span class="dt-checkbox-label"></span></div>',
      entry.name,
      entry.gender,
      entry.date_entered,
      entry.birthday,
      entry.age_in_months,
      entry.weight,
      entry.height,
      entry.weight_for_age_status,
      entry.height_for_age_status,
      entry.weight_for_lt_ht_status,
      entry.imageBase64,
    ];

    table.row(rowNode).data(updatedRowData).draw();
  }

  $("#viewButton").on("click", function () {
    var selectedRow = table.$('input[type="checkbox"]:checked').closest("tr");
    if (selectedRow.length === 0) {
      alert("Please select a row to view.");
      return;
    }

    var rowData = table.row(selectedRow).data();

    $("#viewName").text(rowData[1]);
    $("#viewGender").text(rowData[2]);
    $("#viewDateEntered").text(rowData[3]);
    $("#viewBirthday").text(rowData[4]);
    $("#viewAgeInMonths").text(rowData[5]);
    $("#viewWeight").text(rowData[6]);
    $("#viewHeight").text(rowData[7]);
    $("#viewWeightForAgeStatus").text(rowData[8]);
    $("#viewHeightForAgeStatus").text(rowData[9]);
    $("#viewWeightForLTHTStatus").text(rowData[10]);

    if (rowData[11]) {
      $("#viewImage").attr("src", rowData[11]).show();
    } else {
      $("#viewImage").hide();
    }

    $("#viewEntryModal").modal("show");
  });

  $("#printButton").on("click", function () {
    printModalContent();
  });

  function printModalContent() {
    var printWindow = window.open("", "_blank", "width=800,height=600");
    var modalContent = `
            <html>
            <head>
                <title>Print Barangay Entry</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            </head>
            <body>
                <div class="container">
                    <h1>Barangay Entry</h1>
                    <div id="printContent"></div>
                </div>
            </body>
            </html>
        `;
    printWindow.document.write(modalContent);
    printWindow.document.close();

    var selectedRow = table.$('input[type="checkbox"]:checked').closest("tr");
    if (selectedRow.length === 0) {
      alert("Please select a row to print.");
      printWindow.close();
      return;
    }

    var rowData = table.row(selectedRow).data();
    var printData = `
            <h2>${rowData[1]}</h2>
            <p><strong>Gender:</strong> ${rowData[2]}</p>
            <p><strong>Date Entered:</strong> ${rowData[3]}</p>
            <p><strong>Birthday:</strong> ${rowData[4]}</p>
            <p><strong>Age (in months):</strong> ${rowData[5]}</p>
            <p><strong>Weight:</strong> ${rowData[6]}</p>
            <p><strong>Height:</strong> ${rowData[7]}</p>
            <p><strong>Weight for Age Status:</strong> ${rowData[8]}</p>
            <p><strong>Height for Age Status:</strong> ${rowData[9]}</p>
            <p><strong>Weight for LT/HT Status:</strong> ${rowData[10]}</p>
        `;
    printWindow.document.getElementById("printContent").innerHTML = printData;

    // Print the content after a brief delay
    setTimeout(function () {
      printWindow.print();
      printWindow.close();
    }, 500);
  }
});
