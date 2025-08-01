# Utility Commands for Darwin (macOS)

## System Commands

### File Operations
- `ls -la` - List files with details (same as Linux)
- `find . -name "*.py"` - Find files by pattern
- `grep -r "pattern" .` - Search text in files recursively
- `cd <directory>` - Change directory
- `pwd` - Print working directory
- `mkdir -p <path>` - Create directories recursively
- `rm -rf <path>` - Remove files/directories recursively
- `cp -r <source> <dest>` - Copy files/directories
- `mv <source> <dest>` - Move/rename files

### Process Management
- `ps aux | grep python` - Find Python processes
- `kill -9 <pid>` - Kill process by PID
- `lsof -i :8000` - Find process using port 8000
- `jobs` - List background jobs
- `bg / fg` - Background/foreground jobs

### Network and Ports
- `netstat -an | grep LISTEN` - Show listening ports
- `lsof -i :<port>` - Check what's using a specific port
- `curl -X GET http://localhost:8000` - Test HTTP endpoints

### Git Commands
- `git status` - Check repository status
- `git add .` - Stage all changes
- `git commit -m "message"` - Commit changes
- `git push origin main` - Push to remote
- `git pull origin main` - Pull from remote
- `git branch -a` - List all branches
- `git log --oneline` - Compact commit history

## Docker Commands (Docker Desktop Required)

### Container Management
- `docker ps` - List running containers
- `docker ps -a` - List all containers
- `docker stop <container>` - Stop container
- `docker rm <container>` - Remove container
- `docker images` - List images
- `docker rmi <image>` - Remove image

### Docker Compose
- `docker-compose up -d` - Start services in background
- `docker-compose down` - Stop and remove services
- `docker-compose logs -f` - Follow logs
- `docker-compose ps` - List compose services

## macOS-Specific Notes

### Package Management
- **Homebrew**: `brew install <package>` - Recommended package manager
- **Python**: Use `python3` and `pip3` explicitly
- **Node.js**: Consider using `nvm` for version management

### Development Environment
- **Terminal**: Use Terminal.app or iTerm2
- **Docker**: Docker Desktop for Mac required
- **Azure CLI**: `brew install azure-cli`
- **Azure Functions**: May require Rosetta 2 on Apple Silicon

### File System Differences
- Case-insensitive by default (can cause Git issues)
- Different path separators in some contexts
- Hidden files start with `.` (same as Linux)
- Use `open .` to open current directory in Finder

### Performance Considerations
- **Apple Silicon (M1/M2)**: Some containers may need ARM64 versions
- **DevContainers**: May not work on Apple Silicon for Azure Functions
- **Memory**: Docker Desktop memory allocation may need adjustment
- **File watching**: Large codebases may hit file watching limits

### Environment Variables
- Set in `~/.zshrc` or `~/.bash_profile`
- Export syntax: `export VAR_NAME=value`
- View all: `env` or `printenv`
- View specific: `echo $VAR_NAME`

### Useful macOS Tools
- `pbcopy / pbpaste` - Copy/paste to clipboard
- `open <file>` - Open with default application
- `which <command>` - Find command location
- `say "text"` - Text-to-speech (fun for notifications!)