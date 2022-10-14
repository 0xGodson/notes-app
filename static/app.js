
params = Arg.parse(location.search)
let ipSecret;


function saveSecret(sec) {
  ipSecret = sec;
  console.log(ipSecret);
  if (document.getElementById("ip-secret")) {
    document.getElementById("ip-secret").value = ipSecret;
  }
}


if (params.message) {
  document.getElementsByClassName("container alert alert-success")[0].innerText = params.message;
  document.getElementsByClassName("container alert alert-success")[0].removeAttribute("hidden");
}

if (params.alert) {
  document.getElementsByClassName("container alert alert-danger")[0].innerText = params.alert;
  document.getElementsByClassName("container alert alert-danger")[0].removeAttribute("hidden");
}

function updateTheme() {
  window.open("/challenge/theme");
}
function setTheme(background, font) {
  if (localStorage.getItem("theme")) {
    let current = JSON.parse(localStorage.getItem("theme"))
    let currentBackground = current.background;
    let currentFont = current.font
    if (background.length > 5) {
      localStorage.setItem("theme", JSON.stringify({ background, font: currentFont }))
    }
    if (font.length > 5) {
      localStorage.setItem("theme", JSON.stringify({ background: currentBackground, font }))
    }
    set()
  } else {
    localStorage.setItem("theme", JSON.stringify({ background, font }))
    set()
  }
}

function set() {
  if (localStorage.getItem("theme")) {
    var theme = JSON.parse(localStorage.getItem("theme"))
    document.getElementById("theme-update").style = `background-color:${theme.background};color:${theme.font}`
  }
}


document.addEventListener("DOMContentLoaded", function(){
  document.getElementById("img-theme").addEventListener("click", function() {
    updateTheme()
  })  
});


Object.whoami = Object.create(null); 
if(document.domain.match(/localhost/)){
  Object.whoami = {type: "admin"};
  Object.whoami.markdown = true;
}else{
  Object.whoami = {type: "normal-user"};
}

Object.defineProperty(Object.whoami,'type', {configurable:false,writable:false}); // no overwrite!
try{
  Object.whoami.user = document.head.innerText.split("Welcome")[1].replaceAll("\n", "").replaceAll(" ", "");
}catch{
  Object.whoami.user = "still!"
}

set()
