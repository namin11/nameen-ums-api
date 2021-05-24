//validate reset password form
$().ready(function() {
  $('#resetForm').validate({
    highlight: function(element) {
      $(element)
        .closest('.form-groups')
        .addClass('has-error');
    },
    unhighlight: function(element) {
      $(element)
        .closest('.form-groups')
        .removeClass('has-error');
    },
    errorElement: 'span',
    errorClass: 'help-block',
    errorPlacement: function(error, element) {
      if (element.parent('.input-group').length) {
        error.insertAfter(element.parent());
      } else {
        error.insertAfter(element);
      }
    },
    rules: {
      newPassword: {
        required: true,
        minlength: 8
      },
      confirmPassword: {
        required: true,
        minlength: 8,
        equalTo: '#password'
      }
    },
    messages: {
      newPassword: {
        required: 'Please enter password',
        minlength: 'Your password must contain at least {0} characters'
      },
      confirmPassword: {
        required: 'Please enter confirm password',
        minlength: 'Your password must contain at least {0} characters',
        equalTo: 'Please enter password and confirm password values same'
      }
    },
    submitHandler: function(form) {
      form.submit();
    }
  });
});
