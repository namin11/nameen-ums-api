const Keys = require('../../keys/keys')
const User = require('../../models/user.model')

const constants = require('../../config/constants')

exports.resetPasswordLinkVerification = async (req, res) => {
    try {
      if (req.query.token == undefined) {
        return res.render('notFound');
      }
      let token = req.query.token;
      let message = '';
  
      let user = await User.findOne({
        reset_password_token: token,
      });

  
      if (!user) {

        message = req.flash(
            'error',
            'Your reset password link expire or invalid.'
          );          

        return res.render('message', {
            req: req,
            logoUrl: Keys.BASEURL+`images/logo/logo.png`,
            appBaseUrl: Keys.BASEURL,
            constants: constants,
            message: 'message',
            error: req.flash('error'),
            success: req.flash('success'),
          });
      }

      res.render('forgotPassword', {
        req: req,
        logoUrl: Keys.BASEURL+`images/logo/logo.png`,
        appBaseUrl: Keys.BASEURL,
        constants: constants,
        message: 'message',
        error: req.flash('error'),
        success: req.flash('success'),
      });
    } catch (error) {
        console.log("error..", error)

      return res.render('notFound');
    }
  };