// Function to validate the email format
function validateEmail(email) {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

// Function to validate the password
function validatePassword(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);  // Check for uppercase letter
  const hasLowerCase = /[a-z]/.test(password);  // Check for lowercase letter
  const hasSpecialChar = /[!@#$%^&*(),._-?":{}|<>]/.test(password);  // Check for special character
  const hasNumber = /\d/.test(password);  // Check for number
  const hasWhitespace = /\s/.test(password);  // Check for whitespace
  const hasDot = /\./.test(password);  // Check for dots

  return (
      password.length >= minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasSpecialChar &&
      hasNumber &&
      !hasWhitespace &&
      !hasDot
  );
}

// Function to update Step 3 with values from Steps 1 and 2
function updateOverview() {
  const firstName = document.getElementById("first_name").value;
  const lastName = document.getElementById("last_name").value;
  const fullName = `${firstName} ${lastName}`; // Concatenate first and last name

  document.getElementById("overview-email").textContent = document.getElementById("email").value;
  document.getElementById("overview-username").textContent = document.getElementById("username").value;
  document.getElementById("overview-password").textContent = document.getElementById("password").value.replace(/./g, "*");
  document.getElementById("overview-fullname").textContent = fullName; // Update with the full name
  document.getElementById("overview-contact-number").textContent = document.getElementById("contact-number").value;
}

// Function to highlight invalid fields and show error messages
function highlightInvalidField(field, errorMessageId) {
  field.classList.add("invalid-field");
  document.getElementById(errorMessageId).style.display = "block";
}

// Function to remove highlight and hide error messages
function removeHighlightInvalidField(field, errorMessageId) {
  field.classList.remove("invalid-field");
  document.getElementById(errorMessageId).style.display = "none";
}

$(document).ready(function () {
  $(".wizard").on("stepChanging", function (event, currentIndex, newIndex) {
      let valid = true;

      // Validate Step 1 (Credentials)
      if (currentIndex === 0 && newIndex === 1) {
          // Email validation
          const email = $("#email").val();
          if (email === "" || !validateEmail(email)) {
              highlightInvalidField(document.getElementById("email"), "error-email");
              valid = false;
          } else {
              removeHighlightInvalidField(document.getElementById("email"), "error-email");
          }

          // Username validation
          const username = $("#username").val();
          if (username === "") {
              highlightInvalidField(document.getElementById("username"), "error-username");
              valid = false;
          } else {
              removeHighlightInvalidField(document.getElementById("username"), "error-username");
          }

          // Password validation
          const password = $("#password").val();
          if (password === "") {
              highlightInvalidField(document.getElementById("password"), "error-password");
              valid = false;
          } else if (!validatePassword(password)) {
              highlightInvalidField(document.getElementById("password"), "error-password");
              document.getElementById("error-password").innerHTML =
                  'Password must be at least 8 characters long, include uppercase and lowercase letters, a combination of special characters and numbers, and must not contain whitespace or dots.';
              valid = false;
          } else {
              removeHighlightInvalidField(document.getElementById("password"), "error-password");
          }

          // Confirm Password validation
          const confirmPassword = $("#confirm-password").val();
          if (confirmPassword === "") {
              highlightInvalidField(document.getElementById("confirm-password"), "error-confirm-password");
              valid = false;
          } else if (password !== confirmPassword) {
              highlightInvalidField(document.getElementById("password"), "error-password");
              highlightInvalidField(document.getElementById("confirm-password"), "error-confirm-password");
              valid = false;
              alert("Passwords do not match.");
          } else {
              removeHighlightInvalidField(document.getElementById("confirm-password"), "error-confirm-password");
          }
      }

      // Validate Step 2 (Personal Information)
      if (currentIndex === 1 && newIndex === 2) {
          // Full Name validation
          const firstName = $("#first_name").val();
          const lastName = $("#last_name").val();
          const fullName = `${firstName} ${lastName}`;
          if (firstName === "" || lastName === "") {
              highlightInvalidField(document.getElementById("first_name"), "error-first-name");
              highlightInvalidField(document.getElementById("last_name"), "error-last-name");
              valid = false;
          } else {
              removeHighlightInvalidField(document.getElementById("first_name"), "error-first-name");
              removeHighlightInvalidField(document.getElementById("last_name"), "error-last-name");
          }

          // Gender validation
          if (!$("input[name='gender']").is(":checked")) {
              highlightInvalidField(document.getElementById("male"), "error-gender");
              highlightInvalidField(document.getElementById("female"), "error-gender");
              valid = false;
              alert("Please select a gender.");
          } else {
              removeHighlightInvalidField(document.getElementById("male"), "error-gender");
              removeHighlightInvalidField(document.getElementById("female"), "error-gender");
          }

          // Contact Number validation
          const contactNumber = $("#contact-number").val();
          if (contactNumber === "" || !/^09\d{9}$/.test(contactNumber)) {
              highlightInvalidField(document.getElementById("contact-number"), "error-contact-number");
              valid = false;
          } else {
              removeHighlightInvalidField(document.getElementById("contact-number"), "error-contact-number");
          }
      }

      if (valid) {
          updateOverview();
      }

      return valid;
  });

  $("#registration-form").on("submit", function (e) {
      e.preventDefault();
      $("#success-modal-btn").click();
  });
});
