module.exports = {
    'USER_VALIDATION': {
        register_id_required: 'register Id is required.',
        register_id_length: 'Register Id must be 8 digits',
        valid_email: 'Please enter valid email.',
        password_required: 'Password is required.',
        password_size: 'Password must have atleast 6 letters.',
        password_validation: 'Password should be combination of one uppercase, one lower case, one special character, one digit and minimum 8.',
        old_password_validation: 'Old password should be combination of one uppercase, one lower case, one special character, one digit and minimum 8.',
        new_password_validation: 'New password should be combination of one uppercase, one lower case, one special character, one digit and minimum 8.',
        confirm_password_validation: 'Confirm password should be combination of one uppercase, one lower case, one special character, one digit and minimum 8.',
        first_name_required: 'First name is required.',
        first_name_valid: 'Please enter valid first name',
        first_name_size: 'First name must have atleast 2 and maximum 16 letters.',
        last_required: 'Last name is required.',
        last_name_required: 'Last name is required.',
        last_name_valid: 'Please enter valid last name',
        last_name_size: 'Last name must have atleast 2 and maximum 16 letters.',
        email_valid: 'Please enter valid email',
        old_password_required: 'Old Password is required.',
        old_passwrod_size: 'Old Password must have atleast 6 letters.',
        new_password_required: 'New Password is required.',
        new_passwrod_size: 'New Password must have atleast 6 letters.',
        confirm_password_required: 'Confirm Password is required.',
        confirm_passwrod_size: 'Confirm Password must have atleast 6 letters.',
        daily_practice_remender_required: 'Daily practice remender is required.',
        new_program_added_required: 'New program added is required.',
        subscription_remainder_required: 'Subscription remender is required.',
        social_id_required: 'Social id is required.',
        social_type_required: 'Social type is required.',
        social_type_value: "Social type must be 1 to 3.",
    },

    'CMS_VALIDATION': {
        title_required: 'Title is required.',
        slug_required: 'Slug is required.',
        id_required: 'Id is required.',
        content_required: 'Content is required.',
    },

    'CONTACTUS_VALIDATION': {
        email_required: 'Email is required.',
        subject_required: 'Subject is required.',
        query_required: 'Query is required.',
        valid_email: 'Please enter valid email',
        valid_username: 'Please enter valid username',
    },
    'EMAIL_TEMPLATE_VALIDATION': {
        email_title: 'Title is required.',
        email_title_length: 'Title must have atleast 3 letters.',
        email_keys: 'Keys are required.',
        email_subject: 'Subject is required.',
        email_subject_length: 'Subject must have atleast 2 and maximum 50 letters.',
        email_body: 'Body is required.',
        email_body_value: 'Body must have html value.',
        email_status: 'Status is required.',
        email_status_numeric: 'Please enter valid Status.',
    },

    'SMS_TEMPLATE_VALIDATION': {
        sms_title: 'Title is required.',
        sms_title_length: 'Title must have atleast 3 letters.',
        sms_keys: 'Keys are required.',
        sms_subject: 'Subject is required.',
        sms_subject_length: 'Subject must have atleast 2 and maximum 50 letters.',
        sms_body: 'Body is required.',
        sms_body_value: 'Body must have html value.',
        sms_status: 'Status is required.',
        sms_status_numeric: 'Please enter valid Status.',
    },

    'QUOTE_VALIDATION': {
        quote_required: 'Quote is required.',
        id_required: 'Id is required.',
        form_name_required: 'Form Name is required.',
    },

    'VERSION_VALIDATION': {
        valid_version_number: 'Please enter valid version number',
        format_verion_number: 'Please enter version number in 0.0.0 format.',
        device_type_required: 'Device type is required.',
        force_update_value_required: 'Force update value is required.',
        valid_device_type: 'Please enter valid device type',
        valid_force_update_value: 'Please enter valid force update value',
        force_update_value: 'Force update value must be 0 or 1.',
        version_number_formate: 'Please enter version number in 0.0.0 format.'
    },

    'BROADCAST_MESSAGE': {

        broadcast_name: "Broadcast name is required.",
        broadcast_name_string: "Please enter valid Broadcast name.",
        broadcast_name_length: "Broadcast name must have atleast 2 and maximum 50 letters.",
        broadcast_message: "Broadcast message is required.",
        broadcast_message_string: "Please enter valid Broadcast message.",
        broadcast_message_length: "Broadcast message must have atleast 2 and maximum 150 letters.",
        broadcast_message_language_string: "Please enter valid Broadcast message leanguage.",
        broadcast_message_language_length: "Broadcast message language must have atleast 2 and maximum 3 letters.",
        broadcast_message_id: "Broadcast message '_id' is required.",
        broadcast_message_status_numeric: "Please enter valid Broadcast message status, Numeric Value allowed only.",
        broadcast_message_status_value: "Broadcast message status value must be 0 or 1.",
        contest_id: "Contest Id is required.",
        contest_id_string: "Please enter valid contest id.",
        contest_type: "Contest type is required.",
        contest_type_numeric: "Please enter valid contest type, Numeric Value allowed only.",
        contest_type_value: "Contest type must be 0 to 2.",
        broadcast_type: "Broadcast type is required.",
        broadcast_type_numeric: "Please enter valid broadcast type, Numeric Value allowed only.",
        broadcast_type_value: "Broadcast type must be 1 or 2."
    },

    'TAGS_VALIDATION': {
        name_required: 'Name is required.',
        id_required: 'Id is required.',
        type_required: 'Type is required.',
        status_required: 'Status is required.',
    },

    'DRILLS_VALIDATION': {
        video_required: 'Video link is required.',
        name_required: 'Name is required.',
        id_required: 'Id is required.',
        total_action_required: 'Total actions is required.',
        status_required: 'Status is required.',
        total_suggested_FGM_required: 'Total Suggested FGM is required.',
    },

    'FINISH_TYPES_VALIDATION': {
        name_required: 'Name is required.',
        id_required: 'Id is required.',
        image_required: 'Image is required.',
        status_required: 'Status is required.',
        finish_type_category_required : 'Finish type category is required'
    },

    'MOVES_VALIDATION': {
        name_required: 'Name is required.',
        id_required: 'Id is required.',
        status_required: 'Status is required.',
    },

    'ACTIONS_VALIDATION': {
        name_required: 'Name is required.',
        id_required: 'Id is required.',
        status_required: 'Status is required.',
        start_location_required : 'Start location is required.',
        finish_location_required: 'Finish location is required.',
        finish_type_required: 'Finish type is required.',
        is_solo_possible_required: 'Solo possible is required.',
        sugg_beg_fga_required : 'Beginner FGA is required.',
        sugg_int_fga_required: 'Intermediate FGA is required.',
        sugg_adv_fgm_required: 'Advance FGA is required.',
        pro_tips_required: 'Tips is required.',
        instructions_required : 'Instructions is required.',
        position_required: 'Position is required.',
        move_ids_required: 'Move is required.',
        drill_id_required: 'Drill is required.'
    },

    'VERIFY_TOKEN_VALIDATION': {
        package_name_required: 'Package name is required.',
        product_id_required: 'Product_id is required.',
        purchase_token_required: 'Purchase token is required.',
        apple_receipt_required: 'Apple receipt is required.',
        transaction_id_required: 'Transaction id is required.',
    },

}