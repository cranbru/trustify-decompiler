/**
 * Theme Manager for Trustify
 * Handles dark/light mode switching and persistence
 */
(function() {
    // Initial theme application to prevent flash
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'light') {
        document.documentElement.classList.add('light-theme');
    } else {
        document.documentElement.classList.remove('light-theme');
    }

    // Wait for DOM to attach event listeners
    window.addEventListener('DOMContentLoaded', () => {
        const themeToggle = document.getElementById('theme-toggle');
        
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                // Enable transitions only when switching
                document.documentElement.classList.add('theme-transition');
                
                const isLightTheme = document.documentElement.classList.toggle('light-theme');
                const newTheme = isLightTheme ? 'light' : 'dark';
                
                localStorage.setItem('theme', newTheme);
                
                // Remove transition class after animation to avoid issues with other transitions
                setTimeout(() => {
                    document.documentElement.classList.remove('theme-transition');
                }, 400);
            });
        }
    });
})();
