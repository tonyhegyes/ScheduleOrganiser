/// <reference path="jquery-1.4.4-vsdoc.js" />
/// <reference path="jquery.validate-vsdoc.js" />
/// <reference path="jquery.validate.unobtrusive.js" />

//value - Property that is being validated
//param - Html Element of Property against which 'value' is being validated

(function ($) {
    $.validator.addMethod("localizedcompare", function (value, element, params) {
        if (!this.optional(element)) {
            var otherProp = $('#' + params.otherproperty);

            switch (params.comp) {
                case "mustbenotequalto":
                    return (otherProp.val() != value);
                    break;
                case "mustbeequalto":
                    return (otherProp.val() == value);
                    break;
            }
        }
        return false;
    });
    $.validator.unobtrusive.adapters.add("localizedcompare", ['otherproperty', 'comp'], function (options) {
        var params = {
            otherproperty: options.params.otherproperty,
            comp: options.params.comp
        }

        options.rules['localizedcompare'] = params;
        if (options.message) {
            options.messages['localizedcompare'] = options.message;
        }
    });
}(jQuery));

(function ($) {
    $.validator.addMethod("localizedstringlength", function (value, element, params) {
        if (!value) return false;
        return (value.length >= parseInt(params.min) && value.length <= parseInt(params.max));
    })
    $.validator.unobtrusive.adapters.add("localizedstringlength", ['min', 'max'], function (options) {
        var params = {
            min: options.params.min,
            max: options.params.max
        };

        options.rules['localizedstringlength'] = params;
        if (options.message) {
            options.messages['localizedstringlength'] = options.message;
        }
    });
}(jQuery));

(function ($) {
    $.validator.addMethod("localizedrequired", function (value, element, params) {
        if (!value) return false;
        return true;
    });
    $.validator.unobtrusive.adapters.addBool("localizedrequired");
}(jQuery));
