		$(document).ready(function() {
			// Initialize DataTable
			const monthlyTable = $('#monthly-table').DataTable();
			const yearlyTable = $('#yearly-table').DataTable();
			const archiveTable = $('#archive-table').DataTable(); // Assuming you have an archive table
		
			// Function to get the active table based on the active tab
			function getActiveTable() {
				let activeTab = $('.nav-tabs .nav-link.active').attr('id');
				if (activeTab === 'monthly-tab') {
					return '#monthly-table';
				} else if (activeTab === 'yearly-tab') {
					return '#yearly-table';
				}
				return null;
			}
		
			// Load saved data from localStorage (same as your existing code)
			function loadTableData() {
				const monthlyData = JSON.parse(localStorage.getItem('monthlyData')) || [];
				const yearlyData = JSON.parse(localStorage.getItem('yearlyData')) || [];
				const archiveData = JSON.parse(localStorage.getItem('archiveData')) || [];
		
				monthlyData.forEach(item => {
					monthlyTable.row.add($(`
						<tr>
							<td><input type="checkbox"></td>
							<td>${item.name}</td>
							<td><a href="${item.url}" target="_blank" style="color: blue; text-decoration: underline;">${item.name}</a></td>
							<td>${item.date}</td>
						</tr>
					`)).draw();
				});
		
				yearlyData.forEach(item => {
					yearlyTable.row.add($(`
						<tr>
							<td><input type="checkbox"></td>
							<td>${item.name}</td>
							<td><a href="${item.url}" target="_blank" style="color: blue; text-decoration: underline;">${item.name}</a></td>
							<td>${item.date}</td>
						</tr>
					`)).draw();
				});
		
				archiveData.forEach(item => {
					archiveTable.row.add($(`
						<tr>
							<td></td>
							<td>${item.name}</td>
							<td><a href="${item.url}" target="_blank" style="color: blue; text-decoration: underline;">${item.name}</a></td>
							<td>${item.date}</td>
						</tr>
					`)).draw();
				});
			}
		
			// Save table data to localStorage (same as your existing code)
			function saveTableData() {
				const monthlyData = [];
				const yearlyData = [];
				const archiveData = [];
		
				$('#monthly-table tbody tr').each(function() {
					const cells = $(this).find('td');
					const fileName = cells.eq(1).text();
					const fileURL = cells.eq(2).find('a').attr('href');
					const fileDate = cells.eq(3).text();
					monthlyData.push({ name: fileName, url: fileURL, date: fileDate });
				});
		
				$('#yearly-table tbody tr').each(function() {
					const cells = $(this).find('td');
					const fileName = cells.eq(1).text();
					const fileURL = cells.eq(2).find('a').attr('href');
					const fileDate = cells.eq(3).text();
					yearlyData.push({ name: fileName, url: fileURL, date: fileDate });
				});
		
				$('#archive-table tbody tr').each(function() {
					const cells = $(this).find('td');
					const fileName = cells.eq(1).text();
					const fileURL = cells.eq(2).find('a').attr('href');
					const fileDate = cells.eq(3).text();
					archiveData.push({ name: fileName, url: fileURL, date: fileDate });
				});
		
				localStorage.setItem('monthlyData', JSON.stringify(monthlyData));
				localStorage.setItem('yearlyData', JSON.stringify(yearlyData));
				localStorage.setItem('archiveData', JSON.stringify(archiveData));
			}
		
			// Call loadTableData on page load
			loadTableData();
		
			// Print button click handler
			document.getElementById('print-btn').addEventListener('click', function() {
				let activeTable = getActiveTable();
				if (!activeTable) return;
		
				// Get selected rows
				let selectedRows = $(activeTable).find('tbody input[type="checkbox"]:checked').closest('tr');
				if (selectedRows.length === 0) {
					alert('Please select at least one entry to print.');
					return;
				}
		
				// Collect URLs from the selected entries
				selectedRows.each(function() {
					const fileURL = $(this).find('a').attr('href');
					if (fileURL) {
						// Open the document in a new window for printing
						const printWindow = window.open(fileURL, '_blank');
						printWindow.focus();
						printWindow.print();
					}
				});
			});
		
			// Import button click handler
			document.getElementById('import-btn').addEventListener('click', function() {
				document.getElementById('file-input').click();
			});
		
			document.getElementById('file-input').addEventListener('change', function(event) {
				const file = event.target.files[0];
				if (file) {
					const fileName = file.name;
					const fileDate = new Date().toLocaleDateString();
					const fileURL = URL.createObjectURL(file);
		
					let activeTable = getActiveTable();
					if (activeTable === '#monthly-table') {
						const newRow = `<tr>
											<td><input type="checkbox"></td>
											<td>${fileName}</td>
											<td><a href="${fileURL}" target="_blank" style="color: blue; text-decoration: underline;">${fileName}</a></td>
											<td>${fileDate}</td>
										</tr>`;
						monthlyTable.row.add($(newRow)).draw();
						saveTableData();
					} else if (activeTable === '#yearly-table') {
						const newRow = `<tr>
											<td><input type="checkbox"></td>
											<td>${fileName}</td>
											<td><a href="${fileURL}" target="_blank" style="color: blue; text-decoration: underline;">${fileName}</a></td>
											<td>${fileDate}</td>
										</tr>`;
						yearlyTable.row.add($(newRow)).draw();
						saveTableData();
					}
				}
			});
		
			document.getElementById('archive-btn').addEventListener('click', function() {
				let activeTable = getActiveTable();
				let rowsToArchive = $(activeTable).find('tbody input[type="checkbox"]:checked').closest('tr');
		
				rowsToArchive.each(function() {
					const rowData = $(this).children('td').map(function() {
						return $(this).text();
					}).get();
					
					const fileName = rowData[1];
					const fileURL = $(this).find('a').attr('href');
					const fileDate = rowData[3];
					
					archiveTable.row.add($(`
						<tr>
							<td></td>
							<td>${fileName}</td>
							<td><a href="${fileURL}" target="_blank" style="color: blue; text-decoration: underline;">${fileName}</a></td>
							<td>${fileDate}</td>
						</tr>
					`)).draw();
					
					$(this).remove();
				});
		
				saveTableData();
			});
		
			$('.nav-tabs a').on('shown.bs.tab', function(e) {
				const targetTab = $(e.target).attr('id');
				if (targetTab === 'monthly-tab') {
					$('#example-select-all-yearly').prop('checked', false);
				} else if (targetTab === 'yearly-tab') {
					$('#example-select-all-monthly').prop('checked', false);
				}
			});
		
			$('#example-select-all-monthly').click(function() {
				let isChecked = $(this).is(':checked');
				$('#monthly-table tbody input[type="checkbox"]').prop('checked', isChecked);
			});
		
			$('#example-select-all-yearly').click(function() {
				let isChecked = $(this).is(':checked');
				$('#yearly-table tbody input[type="checkbox"]').prop('checked', isChecked);
			});
		
			window.addEventListener('beforeunload', function() {
				saveTableData();
			});
		});
		

		document.addEventListener('DOMContentLoaded', function() {
			const profileName = localStorage.getItem('profileName');
			const profileImage = localStorage.getItem('profileImage');
	
			console.log('Loaded profile name:', profileName);
			console.log('Loaded profile image:', profileImage);
	
			if (profileName) {
				document.getElementById('dropdown-profile-name').textContent = profileName;
			}

			if (profileImage) {
				document.getElementById('dropdown-profile-picture').src = profileImage;
			}
		});
		document.getElementById('delete-btn').addEventListener('click', function() {
			let activeTable = getActiveTable();
			if (!activeTable) return;
		
			let tableInstance;
			if (activeTable === '#monthly-table') {
				tableInstance = monthlyTable;
			} else if (activeTable === '#yearly-table') {
				tableInstance = yearlyTable;
			} else if (activeTable === '#archive-table') {
				tableInstance = archiveTable;
			}
		
			let selectedRows = $(activeTable).find('tbody input[type="checkbox"]:checked').closest('tr');
			if (selectedRows.length === 0) {
				alert('Please select at least one entry to delete.');
				return;
			}
		
			selectedRows.each(function() {
				tableInstance.row($(this)).remove().draw();
			});
		
			saveTableData();
		});
		