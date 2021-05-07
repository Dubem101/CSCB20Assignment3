function toggleNav() {
    var x = document.getElementById("navbar");
    var items = x.getElementsByClassName("navbar-item");
    for (const item of items) {
        if (item.className === "navbar-item" && item.id != "navbar-home") {
            item.className += " active";
        } else if(item.id != "navbar-home") {
            item.className = "navbar-item";
        }
    }
    return false;
}