---

## 💻 Getting Started

### Prerequisites

- Modern web browser with JavaScript enabled
- No additional installations required

### Usage

1. **Visit the Application**
  - Open [https://local-trustify.vercel.app](https://local-trustify.vercel.app) in your browser
2. **Upload an APK File**
  - Drag and drop an APK file into the designated area, or
  - Click the area to browse and select an APK file from your device
3. **Analyze the Results**
  - View detailed app information and metadata
  - Review requested permissions and Android components
  - Inspect the AndroidManifest.xml
  - Extract and read string resources
4. **Export Findings**
  - Browser's built-in developer tools can capture the analysis
  - Screenshots can document your findings

---

## 🔒 Privacy & Security

- **100% Client-Side Processing**: All APK analysis happens locally in your browser
- **No Server Upload**: Your APK files never leave your device
- **No Data Collection**: Trustify doesn't track or store any analysis data
- **Open Source Approach**: Transparent and auditable code

---

## 🎯 Key Components

### APK Tool Engine

The application uses a WebAssembly-based APK parser compiled with Emscripten, enabling fast and efficient APK analysis directly in the browser without server-side dependencies.

### UI Features

- **Info Tooltips**: Hover over the ℹ️ icons to learn about Android components
- **Progress Tracking**: Real-time progress indicator during analysis
- **Responsive Layout**: Adapts to various screen sizes and devices
- **Syntax Highlighting**: XML files are displayed with proper syntax highlighting

### Supported Android Versions

- Minimum SDK: Android 1.0+ (API level 1)
- Target SDK: Flexible (API level 30+)
- Works with modern Android applications and legacy apps

---

## 📊 Data Extracted

### Application Information

- App name and package name
- Version code and version name
- Supported architectures (ABIs)
- Native libraries (.so files)
- Minimum and target SDK levels

### Android Components

- **Activities**: User-facing screens
- **Services**: Background tasks
- **Broadcast Receivers**: Event handlers
- **Content Providers**: Data sharing
- **Permissions**: All requested system permissions

### Additional Resources

- AndroidManifest.xml (complete XML structure)
- String resources (localized text)
- Application icon

---

## 🚀 Deployment

This project is hosted on **Vercel** and automatically deploys from the main branch. The static HTML/CSS/JS architecture ensures fast loading and low latency.

### Deploying Your Own Instance

1. Fork this repository
2. Connect your fork to Vercel
3. Set the build configuration to deploy static files
4. Access your instance at `https://local-trustify.vercel.app`

