function __showDistro(element) {
	var selectors = element.parent().children();
	var highlight = element.parent().next();

	selectors.each(function() {
		var sthis = $(this);

		if (sthis.is(element)) {
			sthis.addClass("selected");
			highlight.show();
		} else {
			sthis.removeClass("selected");
			highlight.hide();
		}

		highlight = highlight.next();
	});
}

function showDistro(element) {
	__showDistro($(element));
}

function initDistroSpecificCode() {
	$(".distro-menu").each(function() {
		__showDistro($(this).find(":first-child"));
	});
}

window.onload = function() {
	initDistroSpecificCode();
};

