document.addEventListener('DOMContentLoaded', () => {
    // Select all navigation links
    const basicLinks = document.querySelectorAll('[data-path="basic-analysis"]');
    const advancedLinks = document.querySelectorAll('[data-path="advanced-analyst"]');

    // Route to the correct files
    // Based on the current contents, advanced.html contains the Basic View
    // and index.html contains the Advanced View.
    basicLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = 'advanced.html';
        });
    });

    advancedLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = 'index.html';
        });
    });
});
