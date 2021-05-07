document.addEventListener("DOMContentLoaded", function (event) {
    document.querySelectorAll(".dropdownSelect").forEach(element => {
        checkCompleted(element)
        element.addEventListener("change", function () {
            checkCompleted(element)
        });
    });
});

function checkCompleted(element) {
    if (element.value == "completed") {
        document.getElementById(element.id + "-grade").style.display = "block"
    }
    else {
        document.getElementById(element.id + "-grade").style.display = "none"
    }
}