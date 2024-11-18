document.addEventListener('DOMContentLoaded', function () {
	// Load saved profile data from local storage
	const profileData = JSON.parse(localStorage.getItem('profileData'));
	const profileImage = localStorage.getItem('profileImage');

	if (profileData) {
		// Update profile details on the page
		document.getElementById('profile-first-name').textContent = profileData.firstName;
		document.getElementById('profile-last-name').textContent = profileData.lastName;
		document.getElementById('profile-description').textContent = profileData.username;
		document.getElementById('profile-email').textContent = profileData.email;
		document.getElementById('profile-birth').textContent = profileData.birth_date;
		document.getElementById('profile-gender').textContent = profileData.gender || 'Not specified';
		document.getElementById('profile-contact').textContent = profileData.contactNumber;
		// Update the dropdown profile name
		document.getElementById('dropdown-profile-name').textContent = `${profileData.firstName} ${profileData.lastName}`;
	}

	if (profileImage) {
		// Load saved profile image
		document.querySelector('.avatar-photo').src = profileImage;
		document.getElementById('dropdown-profile-picture').src = profileImage;
	}

	// Handle form submission
	document.getElementById('profile-form').addEventListener('submit', function (e) {
		e.preventDefault(); // Prevent form submission

		// Gather form data
		const firstName = document.getElementById('first-name').value;
		const lastName = document.getElementById('last-name').value;
		const username = document.getElementById('username').value;
		const email = document.getElementById('email').value;		
		const birth_date = document.getElementById('birth_date').value;
		const gender = document.querySelector('input[name="gender"]:checked')?.nextElementSibling.textContent || 'Not specified';
		const contactNumber = document.getElementById('contact-number').value;

		// Update profile details on the page
		document.getElementById('profile-first-name').textContent = firstName;
		document.getElementById('profile-last-name').textContent = lastName;
		document.getElementById('profile-description').textContent = username;
		document.getElementById('profile-email').textContent = email;
		document.getElementById('profile-birth').textContent = birth_date;
		document.getElementById('profile-gender').textContent = gender;
		document.getElementById('profile-contact').textContent = contactNumber;

		// Save profile data to local storage
		const profileData = {
			firstName,
			lastName,
			username,
			email,
			birth_date,
			gender,
			contactNumber,
		};
		localStorage.setItem('profileData', JSON.stringify(profileData));
		localStorage.setItem('profileImage', croppedImageDataURL);

		// Update the dropdown profile name
		document.getElementById('dropdown-profile-name').textContent = `${firstName} ${lastName}`;

		// Show success message
		const alertMessage = document.getElementById('alert-message');
		alertMessage.className = 'alert alert-success';
		alertMessage.textContent = 'Your information has been successfully updated!';
		alertMessage.style.display = 'block';

		// Hide the alert after a few seconds
		setTimeout(() => {
			alertMessage.style.display = 'none';
		}, 3000);

		// Show confirmation modal
		$('#confirmationModal').modal('show');

		// Clear form fields
		document.getElementById('profile-form').reset();
	});

	// Image upload and cropping logic
	var previewImage = document.getElementById('preview-image');
	var image = document.getElementById('image');
	var cropper;
	var uploadPhoto = document.getElementById('upload-photo');
	var errorMessage = document.createElement('div');
	errorMessage.className = 'alert alert-danger';
	errorMessage.style.display = 'none';
	document.querySelector('.modal-body').appendChild(errorMessage);

	uploadPhoto.addEventListener('change', function (event) {
		var files = event.target.files;
		if (files && files.length > 0) {
			var file = files[0];
			var fileType = file.type;
			var allowedTypes = ['image/jpeg', 'image/png'];

			if (!allowedTypes.includes(fileType)) {
				errorMessage.textContent = 'Please upload a valid image file (PNG or JPEG).';
				errorMessage.style.display = 'block';
				uploadPhoto.value = '';
				return;
			} else {
				errorMessage.style.display = 'none';
			}

			var reader = new FileReader();

			reader.onload = function (e) {
				previewImage.src = e.target.result;
				previewImage.style.display = 'block';
				document.querySelector('.img-preview-container').style.display = 'block';
				document.querySelector('.cropper-container').style.display = 'none';
				document.getElementById('crop-button').style.display = 'block';

				if (cropper) {
					cropper.destroy();
					cropper = null;
				}
				image.src = '';
			};

			reader.readAsDataURL(file);
		}
	});

	document.getElementById('crop-button').addEventListener('click', function () {
		document.querySelector('.img-preview-container').style.display = 'none';
		document.querySelector('.cropper-container').style.display = 'block';
		document.getElementById('save-button').style.display = 'block';

		image.src = previewImage.src;

		cropper = new Cropper(image, {
			autoCropArea: 1,
			dragMode: 'move',
			aspectRatio: 1,
			restore: false,
			guides: false,
			center: false,
			highlight: false,
			cropBoxMovable: true,
			cropBoxResizable: true,
			toggleDragModeOnDblclick: false
		});
	});

	document.getElementById('save-button').addEventListener('click', function () {
		if (cropper) {
			var canvas = cropper.getCroppedCanvas({
				width: 160,
				height: 160
			});

			var croppedImageDataURL = canvas.toDataURL();

			var avatarPhoto = document.querySelector('.avatar-photo');
			avatarPhoto.src = croppedImageDataURL;

			var dropdownProfilePicture = document.getElementById('dropdown-profile-picture');
			dropdownProfilePicture.src = croppedImageDataURL;

			localStorage.setItem('profileImage', croppedImageDataURL);

			$('#modal').modal('hide');

			cropper.destroy();
			cropper = null;
		}
	});

	$('#modal').on('hidden.bs.modal', function () {
		if (cropper) {
			cropper.destroy();
			cropper = null;
		}

		uploadPhoto.value = '';
		previewImage.src = '';
		previewImage.style.display = 'none';
		document.querySelector('.img-preview-container').style.display = 'none';
		document.querySelector('.cropper-container').style.display = 'none';
		document.getElementById('crop-button').style.display = 'none';
		document.getElementById('save-button').style.display = 'none';
		errorMessage.style.display = 'none';
	});
});
document.addEventListener("DOMContentLoaded", function() {
    const uploadPhotoInput = document.getElementById("upload-photo");
    const previewImage = document.getElementById("preview-image");
    const removeButton = document.getElementById("remove-image");
    const profilePhoto = document.getElementById("profile-photo");

    uploadPhotoInput.addEventListener("change", function(event) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                previewImage.src = e.target.result;
                previewImage.style.display = "block";
                removeButton.style.display = "inline-block";
            }
            reader.readAsDataURL(file);
        }
    });

    removeButton.addEventListener("click", function() {
        if (confirm("Are you sure you want to remove your profile image?")) {
            profilePhoto.src = "{% static 'src/images/user.png' %}";
            previewImage.style.display = "none";
            removeButton.style.display = "none";
        }
    });
});
