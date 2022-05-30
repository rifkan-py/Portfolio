const links = [...document.querySelectorAll(".links a")];
const sections = [...document.querySelectorAll(".section")];

window.onscroll = () => {
  sections.forEach((sec) => {
    let top = window.scrollY;
    let offset = sec.offsetTop - 150;
    let height = sec.offsetHeight;
    let id = sec.getAttribute("id");

    if (top >= offset && top < offset + height) {
      links.forEach((link) => {
        link.classList.remove("active");
        document
          .querySelector(`.links a[href*='${id}']`)
          ?.classList.add("active");
      });
    }
  });
};
