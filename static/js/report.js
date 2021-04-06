const scanDetails = document.querySelector(".scan-details");
const payloadsTried = document.querySelector(".payloads-tried");
const scanLogs = document.querySelectorAll(".scan-logs");
const payloads = document.querySelectorAll(".payloads");
const testLogs = document.querySelectorAll(".test-logs");
const scanDetails1 = document.querySelector(".scan-details1");
const risk = document.querySelectorAll(".risk");
const rec = document.querySelector(".rec");
const reco = document.querySelector(".reco");
const recom = document.querySelectorAll(".recom");
const rec1 = document.querySelector(".rec1");
const reco1 = document.querySelector(".reco1");
const recom1 = document.querySelectorAll(".recom1");
const sqlid = document.querySelector(".sqlid");
const xssd = document.querySelector(".xssd");

reco.addEventListener("click", showRec);

function showRec() {
  recom.forEach((e) => {
    if (e.style.display == "none") {
      e.style.display = "block";
    } else {
      e.style.display = "none";
    }
  });
}
reco1.addEventListener("click", showRec1);

function showRec1() {
  recom1.forEach((e) => {
    if (e.style.display == "none") {
      e.style.display = "block";
    } else {
      e.style.display = "none";
    }
  });
}

if (sqlid.innerText == "True") {
  rec.className = "active";
}
if (xssd.innerText == "True") {
  rec1.className = "active";
}

risk.forEach((e) => {
  if (e.innerText == "High") {
    e.style.color = "red";
  } else {
    e.style.color = "#008000";
  }
});

scanDetails.addEventListener("click", reveal);

function reveal() {
  scanLogs.forEach((e) => {
    if (e.style.display == "none") {
      e.style.display = "block";
    } else {
      e.style.display = "none";
    }
  });
}

payloadsTried.addEventListener("click", show);

function show() {
  payloads.forEach((e) => {
    if (e.style.display == "none") {
      e.style.display = "block";
    } else {
      e.style.display = "none";
    }
  });
}

scanDetails1.addEventListener("click", opened);

function opened() {
  testLogs.forEach((e) => {
    if (e.style.display == "none") {
      e.style.display = "block";
    } else {
      e.style.display = "none";
    }
  });
}