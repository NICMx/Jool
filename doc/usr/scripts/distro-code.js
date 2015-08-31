function getIndex(node) {
	var family = node.parentNode.getElementsByTagName("span");
	for (var i = 0; i < family.length; i++) {
		if (family[i] == node)
			return i;
	}

	return -1;
}

function markSelected(menu, index) {
	var family = $(menu).children("span");

	for (var i = 0; i < family.length; i++) {
		if (i == index)
			$(family[i]).addClass("selected");
		else
			$(family[i]).removeClass("selected");
	}
}

function hideAllBut(menu, index) {
	var family = $(menu).parent().children("div");
	index++;

	for (var i = 1; i < family.length; i++) {
		if (i == index)
			$(family[i]).show();
		else
			$(family[i]).hide();
	}
}

function showCode(caller) {
	var index = getIndex(caller);
	markSelected(caller.parentNode, index);
	hideAllBut(caller.parentNode, index);
}

function initDistroSpecificCode() {
	$(".distro-menu").each(function() {
		markSelected(this, 0);
		hideAllBut(this, 0);
	});
}

window.onload = function() {
	initDistroSpecificCode();
};

