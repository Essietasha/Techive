window.addEventListener('DOMContentLoaded', () => {
    const home = document.querySelector('.homebg');
    const categorySelect = document.querySelector('.categoryDivEl');
    const signupLoginDiv = document.querySelector('.signupRightDiv');

    if (home) home.classList.add('homeslide');
    if (categorySelect) categorySelect.classList.add('slidein');
    if (signupLoginDiv) signupLoginDiv.classList.add('slideinslower');
})
