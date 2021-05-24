module.exports = {

    'USER': {
        create_student_success: 'Create Studend successfully.',
        create_faculty_success : 'Create Faculty successfully.',
        get_student_success : 'Get Student data successfully.',
        get_faculty_success : 'Get Faculty data successfully.',
        register_id_already_exist: 'Register Id already in use.',
        login_success: 'Login successfully.',
        not_admin: 'Only Admin can access this API',
        not_faculty: 'Only Faculty can access this API',
        not_student: 'Only Stuent can access this API',
        social_login_success: 'Social login successfully.',
        logout_success: 'Logout successfully.',
        logout_fail: 'Error while logging you out.',
        resetPassword_success: 'Your password has been updated successfully.',
        forgotPassword_success: 'Your password has been updated successfully.',
        userDetail_not_available: 'User details not available at this time.',
        invalidOldPassword: 'Please enter a valid old password.',
        passwordMinLength: 'Your password must contain at least 6 characters.',
        passwordUpdate_success: 'Your password successfully changed.',
        profile_fetch_success: 'Profile fetch successfull.',
        profile_update_success: 'Profile updated successfully.',
        email_not_found: 'Username/Email is not registered.',
        forgotPassword_email_success: 'Please check your email to reset password.',
        resend_email_success: 'Resend mail send successfully.',
        forgotPassword_email_fail: 'Error while sending link.',
        resetPassword_token_success: 'Token varified.',
        resetPassword_token_fail: 'Token expired.',
        password_update_fail: 'Error while updating password.',
        set_new_password_fail: 'Your link has been expired.',
        set_new_password_success: 'Your password has been reset successfully.',
        user_name_already_exist: 'This username has already been taken. Please enter a different username.',
        email_already_exist: 'Email already in use.',
        delete_account: 'Your account is deleted.',
        not_verify_account: 'Please verify your account.',
        deactive_account: 'Your account is deactivated by administrator.',
        inactive_account: 'Your account is deactivated by administrator.',
        account_verify_success: `Your account has been verified successfully. Please click 'Continue' in the app to proceed.`,
        account_verify_fail: 'Your account verify link expire or invalid.',
        password_mismatch: 'New password and confirm password not matched.',
        invalid_username_password: "Invalid email or password.",
        invalid_password: "Invalid password.",
        user_data_retrieved_success : 'User data retrieved successfully.',
        user_activation : 'User activated successfully.',
        user_inactivation : 'User inactivated successfully.',
        user_deactivate : 'User deactivated successfully.',
        user_details_not_available : 'User details not available.',
        get_user_profile : 'User profile get profile.',
        user_deleted: 'User deleted successfully.',
        get_user_notificatuon_setting : 'User notification setting details.',
        update_user_notificatuon_setting : 'User notification setting details update successfully.',
        user_details_not_found: 'User not found, Please sign up.',
        get_user_skill_message: "get user skill message successfully.",
        logout_success: "Logout successfully.",
        account_already_verify: "Account alredy verify",
        create_announcement: "Create announcement successfully.",
        upload_time_table: "Upload time table successfully.",
        delete_faculty: "Delete faculty successfully.",
        delete_student: "Delete student successfully.",
        user_not_found: 'User not found',
        delete_program: "Delete program successfully.",
        program_not_found: 'program not found',
        delete_course: "Delete course successfully.",
        course_not_found: 'course not found',
        delete_announcement: "Delete announcement successfully.",
        announcement_not_found: 'announcement not found',
        get_announcement_details: 'get Announcement details successfully.',
        announcemente_update_success: 'Edit Announcement details successfully.'
    },
    'GENERAL': {
        
        general_error_content: 'Something went wrong. Please try again later.',
        unauthorized_user: 'Unauthorized, please login.',
        invalid_user: 'You are not authorized to do this operation.',
        invalid_login: 'You are not authorized.',
        blackList_mail: `Please enter a valid email, we don't allow dummy emails.`
    },

    'COUNTRY': {
        county_list_fetch_success: 'Country list fatched successfully.',
        state_list_fetch_success: 'State list fatched successfully.',
        city_list_fetch_success: 'City list fatched successfully.',
        state_list_not_found: 'State list not found Please check Conutry Name.',
        city_list_not_found: 'City list not found Please check State Name.',
    },

    'ADMIN': {
        add_quote_fail: 'Error while adding quate.',
        add_quote_success: 'Quote has been added successfully.',
        quotes_empty: 'No quotes available.',
        update_quote_fail: 'Error while updating quate.',
        update_quote_success: 'Quote has been updated successfully.',
        cms_create_success: 'CMS added successfully.',
        cms_get_success: 'Get CMS successfully.',
        selected_language_not_found: 'Selected language not found.',
        cms_not_found: 'CMS not found.',
        cms_title_exist: 'CMS title already exist.',
        cms_slug_exist: 'CMS slug already exist.',
        cms_update_success: 'CMS has been updated successfully.',
        version_already_exists: 'Entered version already exists.',
        version_number_lower: 'Entered version number is lower.',
        version_number_created_success: 'Version has been created successfully.',
        version_no_update: "Application is up to date!",
        version_force_update: "A new version available. Please update to use more features.",
        send_contact_request_fail: 'Error while sending contact request.',
        send_contact_request_success: 'Contact request has been sent successfully.',
        get_contactus_req: 'Get contactUs request successfully.',
        get_quotes: 'Get quotes successfully.',
        get_version: 'Get version successfully.',
        contactus_req_empty: 'No ContactUs Request.',
        close_contact_request_success: 'Contact request query closed successfully.',
        close_contact_request_already_closed: 'Contact request query already closed.',
        contact_close_req_mail_subject: 'Your contact us request closed.',
        contact_req_mail_subject: 'You have new contact request.',
        add_tag_fail: 'Error while adding tag.',
        add_tag_success: 'Tag has been added successfully.',
        update_tag_success: 'Tag has been updated successfully.',
        tags_empty: 'No tag available.',
        add_finish_type_fail: 'Error while adding finish type.',
        add_finish_type_success: 'Finish type has been added successfully.',
        update_finish_type_success: 'Finish type has been updated successfully.',
        finish_type_empty: 'No finish type available.',
        finish_type_cat_empty: 'No finish type categories available.',
        locations_empty: 'No locations available.',
        get_tags: 'Get tags successfully.',
        get_finishtypes: 'Get finish types successfully.',
        get_locations: 'Get locations successfully.',
        add_move_fail: 'Error while adding move.',
        add_move_success: 'Move has been added successfully.',
        update_move_success: 'Move has been updated successfully.',
        moves_empty: 'No move available.',
        get_moves: 'Get moves successfully.',
        add_drill_fail: 'Error while adding tag.',
        add_drill_success: 'Drill has been added successfully.',
        update_drill_success: 'Drill has been updated successfully.',
        drills_empty: 'No drill available.',
        get_drills: 'Get drills successfully.',
        add_action_fail: 'Error while adding tag.',
        add_action_success: 'Action has been added successfully.',
        update_action_success: 'Action has been updated successfully.',
        actions_empty: 'No drill available.',
        get_actions: 'Get actions successfully.',
        get_finish_types: 'Get actions successfully.',
        workout_list_fetch_success: 'Workout list fetch successfully.',
        update_workout_status_success: 'Update workout status successfully.',
        workout_create_success: 'Workout create successfully.',
        add_proper_drill_id: 'Add proper drill_id.',
        program_create_success: 'Program create successfully.',
        program_list_fetch_success: 'Program list fetch successfully.',
        update_program_status_success: 'Update program status successfully.',
        add_proper_workot_id: 'Add proper workout_id.',
        workout_status_not_draft: 'Workout update only when draft status.',
        program_status_not_draft: 'Program update only when draft status.',
        drill_status_not_draft: 'Drills status is not draft.',
        workout_data_fetch_success: 'Workout data fetch successfully.',
        program_data_fetch_success: 'Program data fetch successfully.',
        update_workout_success: 'Workout has been updated successfully.',
        update_program_success: 'Program has been updated successfully.',
        some_drill_status_is_draft: `some drill's status is draft`,
        some_workout_status_is_draft: `some workout's status is draft`,
        update_workout_order: `Workout order has been changed successfully.`,
        update_program_order: `Program order has been changed successfully.`,
        user_excel_file: `User data exported successfully.`,
        revenue_list_fetch_success: `Payment list fetch successfully.`,
        valid_zip_file: "Only ZIP file is allowed.",
        cms_not_found: "CMS details not found.",
        index_file_not_found: "Index.html is missing in the root directory.",
        cms_upload_success: "CMS uploaded successfully.",
        cms_backup_error: "An error occurred during to backup the data."
    },

    'EMAIL': {
        title_already_exists: 'Title already exists.',
        email_format_created_success: 'Email format created successfully.',
        email_format_updated_success: 'Email format updated successfully.',
        no_email_format_exists: 'No email format exists.',
        email_template_retrieve: 'Email Template retrieved successfully.',
        email_template_deleted: 'Email Template deleted successfully.'
    },

    'COURSE': {
        course_not_found: 'Please select correct courese_id',
        get_all_courese_assign: 'all assigned coures.',
        select_course_success: "Courses selected.",
        create_course_success : 'Create course successfully.',

    },

    'PROGRAM': {
        course_not_found: 'Please select correct courese_id',
        get_all_courese_assign: 'all assigned coures.',
        select_course_success: "Courses selected.",
        create_course_success : 'Create program successfully.',
        get_program_list: 'Get all programs'

    },

    

    'FACULTY': {
        faculty_not_found: 'Please select correct faculty_id'
    },

    'BROADCAST_MESSAGE': {

        broadcast_message_exist: "Broadcast message already exist.",
        broadcast_message_success: "Broadcast message added successfully.",
        broadcast_message_retrieved: "Broadcast message retrieved successfully.",
        broadcast_message_not_found: "Broadcast message not found.",
        broadcast_message_update: "Broadcast message updated successfully.",
        broadcast_message_contest: "Please select valid contest type.",
        not_winner: "You can not broadcast a message as you are not a 1st rank winner.",
        message_send_success: "You have broadcast a message successfully.",
        message_skip_success: "You have skipped a message broadcast successfully.",
        message_already_broadcasted: "You already have broadcasted a message.",
        skip_message_broadcasted: "You have skipped message broadcast for this contest.",
        broadcast_message_id: "Broadcast message ID required.",
        broadcast_message_activated: "Broadcast message activated successfully.",
        broadcast_message_inactivated: "Broadcast message inactivated successfully.",
        broadcast_message_status_fail: "Please enter a valid broadcast message status.",
        broadcast_message_in_use: "Sorry you can't delete this broadcast message as it is in use.",
        broadcast_message_delete: "Broadcast message deleted successfully."

    },

    'CONTACTUS': {
        query_created_success: 'Query created successfully.',
    },

    'DRILL': {
        drill_data_fetch_success: 'Drill data fetch successfully.',
        drill_data_not_available: 'Drill data not availbale.',
        add_action_logs: 'Add action logs successfully.'
    },

    'WORKOUT': {
        workout_data_fetch_success: 'Workout data fetch successfully.',
        workout_data_not_available: 'Workout data not availbale.',
        workout_list_fetch_success: 'Workout list fetch successfully.',
        already_favourite: 'This workout is already favourite.',
        add_favourite_success: 'Workout add favourite successfully.',
        add_favourite_fail: 'Error while add Workout favourite',
        remove_favourite_success: 'Workout remove favourite successfully.',
        remove_favourite_fail: 'Error while remove Workout favourite',
        no_favourite_workout: `This user hasn't any favourite workout`,
        get_favourite__success: 'get users favourite list successfully',
        already_unfavourite: 'This workout is already remove from favourite.',
        workout_tag_fetch_success: 'Workout list tag wise fetch successfully.',
        workout_tag_not_available: 'Workout list tag wise not availbale.'
    },

    'PROGRAM': {
        program_list_fetch_success: 'Program list fetch successfully.',
        already_enrolled_program: 'This program is already enrolled.',
        already_unenrolled_program: 'This program is already unenrolled.',
        add_enrolled_program_success: 'Program enrolled successfully.',
        unenrolled_program_success: 'Program unenrolled successfully.',
        unenrolled_program_fail: 'Error while program unenrolled.',
        program_data_not_available: 'Program data is not availbale.',
        program_data_fetch_success: 'Program data fetch successfully.',
        enrolled_program_list_fetch_success: 'Enrolled program list fetch successfully.'
    },
    'ANALYTICS': {
        user_performed_list_data_not_available: "User performed list data not available.",
        user_performed_list_data_fetch_success: "User performed list data fetch successfully."
    },

    'ATTENDANCE': {
        add_student_attendance: "Add studnet attendance successfully.",
        get_student_attendance: "Get studnet attendance successfully.",
        add_faculty_attendance: "Add faculty attendance successfully.",
        get_faculty_attendance: "Get faculty attendance successfully."
    },

    'NOTIFICATION': {
        notification_fetch_success: 'Notification fetch successfully.'
    },

    'SYNC': {
        sync_fetch_success: 'Sync data fetch successfully.'
    },

    'CMS': {
        cms_list_fetch_success: 'CMS list fetch successfully.'
    },

    'APPLE': {
        UNABLE_TO_CONNECT_SERVER: 'Unable to connect server.',
        RECEIPT_GENERATED_FROM_SANDBOX : 'Receipt was generated from sandbox.',
        NO_RECEIPT_CONTENT_FOUND : 'No receipt content found.',
        RECEIPT_GENERATED_FROM_LIVE : 'Receipt was generated from live.',
        INVALID_RECEIPT : 'Receipt is Invalid.',
        INVALID_SECRET : 'Secret is Invalid.',
        SUBSCRIBE_SUCCESS : 'You have successfully subscribed.', 
        ios_transaction_id_use: 'This Apple ID already in use for the subscription, try with others.',
        android_transaction_id_use: 'This Google account already in use for the subscription, try with others.'
    },
    'STUDENTRESULT': {
        student_result_list_success: 'Students result list fetch successfully.',
        create_student_result_success:'Student result added successfully.',
        student_result_fetch_success:'Students result fetch successfully.',
        student_update_success:"Students result updated successfully.",
        result_not_found:"No student result found.",
        result_deleted:"Student result deleted successfully."
    },




    // add_new_inspector_success: 'User added successfully.',
    // add_new_inspector_fail: 'Error while adding user.',
    // delete_inspector_success: 'User deleted successfully.',
    // user_list_fetch_success: 'User list fatched successfully.',
    // userList_empty: 'No user available',
    // image_success: 'Image uploaded successfully',
}