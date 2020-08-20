$(document).ready(function () {
    $("#searchInput").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#listProducts a").filter(function() {
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
    
    $(".analysis").hover(
        function () {
            $(this).addClass('shadow-lg').css('cursor', 'pointer');
        }, function () {
            $(this).removeClass('shadow-lg');
        }
    );
});

function resizeGraph(ele){
    setTimeout(() => { 
        var a= ele.getAttribute('data-target').substr(1); 
        eval(document.getElementById(a).querySelector('script').innerHTML)
    },240);
}

function modeInteractive(){
    var div_interactive = document.getElementById("interactive_mode");
    var div_print = document.getElementById("print_mode")
    div_interactive.style.display = "block";
    div_print.style.display = "none";
}

function modePrint(){
    var div_interactive = document.getElementById("interactive_mode");
    var div_print = document.getElementById("print_mode")
    div_interactive.style.display = "none";
    div_print.style.display = "block";
}