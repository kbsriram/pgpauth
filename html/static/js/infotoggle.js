$(function() {
    $(".info_toggle").click(function(ev) {
        var $id = $(".info_description");
        if ($id.is(":hidden")) {
            $id.slideDown('fast');
        }
        else {
            $id.slideUp('fast');
        }
        return false;
    });
});