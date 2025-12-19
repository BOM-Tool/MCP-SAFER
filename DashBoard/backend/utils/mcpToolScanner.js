/**
 * MCP Protocol을 사용하여 Tool 목록을 가져오는 유틸리티
 * MCP Server에 직접 연결하여 tools/list 메서드 호출
 */

const { spawn } = require('child_process');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

/**
 * MCP Server에 stdio로 연결하여 tools/list 호출
 * @param {Object} config - 서버 연결 설정
 * @param {string} config.command - 실행 명령어
 * @param {Array} config.args - 명령어 인자
 * @param {Object} config.env - 환경 변수
 * @param {number} timeout - 타임아웃 (밀리초, 기본 10초)
 * @returns {Promise<{tools: string[], success: boolean}>}
 */
async function getToolsFromMcpServer(config, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const { command, args = [], env = {} } = config;
    
    if (!command) {
      return reject(new Error('command가 필요합니다.'));
    }

    const tools = [];
    let stdoutData = '';
    let stderrData = '';
    let responseReceived = false;

    // 환경 변수 준비
    const processEnv = { ...process.env, ...env };

    // MCP Server 프로세스 실행
    const server = spawn(command, args, {
      env: processEnv,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // 타임아웃 설정
    const timeoutId = setTimeout(() => {
      if (!responseReceived) {
        server.kill();
        responseReceived = true;
        reject(new Error('MCP Server 응답 타임아웃'));
      }
    }, timeout);

    // stdout 데이터 수집
    server.stdout.on('data', (data) => {
      stdoutData += data.toString();
      
      // JSON-RPC 메시지 파싱 시도
      const lines = stdoutData.split('\n').filter(line => line.trim());
      for (const line of lines) {
        try {
          const message = JSON.parse(line);
          
          // tools/list 응답 확인
          if (message.id === 2 && message.result && message.result.tools) {
            responseReceived = true;
            clearTimeout(timeoutId);
            
            message.result.tools.forEach(tool => {
              if (tool.name) {
                tools.push(tool.name);
              }
            });
            
            server.kill();
            resolve({
              tools: [...new Set(tools)].sort(),
              success: true
            });
            return;
          }
        } catch (e) {
          // JSON 파싱 실패는 무시 (부분 메시지일 수 있음)
        }
      }
    });

    // stderr 처리
    server.stderr.on('data', (data) => {
      stderrData += data.toString();
    });

    // 프로세스 종료 처리
    server.on('close', (code) => {
      clearTimeout(timeoutId);
      if (!responseReceived) {
        if (tools.length > 0) {
          resolve({
            tools: [...new Set(tools)].sort(),
            success: true
          });
        } else {
          reject(new Error(`MCP Server 종료 (code: ${code}). stderr: ${stderrData.substring(0, 200)}`));
        }
      }
    });

    // 에러 처리
    server.on('error', (error) => {
      clearTimeout(timeoutId);
      if (!responseReceived) {
        responseReceived = true;
        reject(new Error(`MCP Server 실행 실패: ${error.message}`));
      }
    });

    // initialize 메시지 전송
    const initMessage = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {
          tools: {}
        },
        clientInfo: {
          name: "bom-tool-scanner",
          version: "1.0.0"
        }
      }
    };

    // tools/list 메시지 전송
    const toolsListMessage = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {}
    };

    // 메시지 전송 (초기화 후 약간의 지연을 두고 tools/list 전송)
    try {
      server.stdin.write(JSON.stringify(initMessage) + '\n');
      
      // initialize 후 약간의 지연 (서버가 준비될 시간)
      setTimeout(() => {
        if (!responseReceived) {
          server.stdin.write(JSON.stringify(toolsListMessage) + '\n');
        }
      }, 500);
    } catch (error) {
      clearTimeout(timeoutId);
      if (!responseReceived) {
        responseReceived = true;
        reject(new Error(`메시지 전송 실패: ${error.message}`));
      }
    }
  });
}

/**
 * SSH를 통해 원격 MCP Server에 연결하여 tools/list 호출
 * @param {Object} config - SSH 연결 설정
 * @param {string} config.ssh_host - SSH 호스트
 * @param {string} config.ssh_user - SSH 사용자
 * @param {string} config.ssh_key - SSH 키 파일 경로
 * @param {string} config.command - 원격에서 실행할 명령어
 * @param {Array} config.args - 명령어 인자
 * @param {Object} config.env - 환경 변수
 * @param {number} timeout - 타임아웃 (밀리초, 기본 15초)
 * @returns {Promise<{tools: string[], success: boolean}>}
 */
async function getToolsFromSshServer(config, timeout = 15000) {
  const { ssh_host, ssh_user, ssh_key, command, args = [], env = {} } = config;

  if (!ssh_host || !ssh_user || !command) {
    throw new Error('SSH 연결 정보가 불완전합니다.');
  }

  // SSH 키 옵션
  const keyOption = ssh_key ? `-i ${ssh_key}` : '';
  
  // 환경 변수 설정
  const envVars = Object.entries(env)
    .map(([key, value]) => `${key}=${value}`)
    .join(' ');

  // 원격 명령어 구성
  const remoteCommand = envVars 
    ? `${envVars} ${command} ${args.join(' ')}`
    : `${command} ${args.join(' ')}`;

  // SSH 명령어 구성
  const sshCommand = `ssh ${keyOption} -o StrictHostKeyChecking=no -o ConnectTimeout=5 -T ${ssh_user}@${ssh_host} '${remoteCommand}'`;

  return new Promise((resolve, reject) => {
    const tools = [];
    let stdoutData = '';
    let stderrData = '';
    let responseReceived = false;

    // SSH로 원격 명령어 실행
    const sshProcess = spawn('sh', ['-c', sshCommand], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // 타임아웃 설정
    const timeoutId = setTimeout(() => {
      if (!responseReceived) {
        sshProcess.kill();
        responseReceived = true;
        reject(new Error('SSH MCP Server 응답 타임아웃'));
      }
    }, timeout);

    // stdout 데이터 수집
    sshProcess.stdout.on('data', (data) => {
      stdoutData += data.toString();
      
      // JSON-RPC 메시지 파싱
      const lines = stdoutData.split('\n').filter(line => line.trim());
      for (const line of lines) {
        try {
          const message = JSON.parse(line);
          
          if (message.id === 2 && message.result && message.result.tools) {
            responseReceived = true;
            clearTimeout(timeoutId);
            
            message.result.tools.forEach(tool => {
              if (tool.name) {
                tools.push(tool.name);
              }
            });
            
            sshProcess.kill();
            resolve({
              tools: [...new Set(tools)].sort(),
              success: true
            });
            return;
          }
        } catch (e) {
          // JSON 파싱 실패 무시
        }
      }
    });

    // stderr 처리
    sshProcess.stderr.on('data', (data) => {
      stderrData += data.toString();
    });

    // 프로세스 종료 처리
    sshProcess.on('close', (code) => {
      clearTimeout(timeoutId);
      if (!responseReceived) {
        if (tools.length > 0) {
          resolve({
            tools: [...new Set(tools)].sort(),
            success: true
          });
        } else {
          reject(new Error(`SSH 연결 종료 (code: ${code}). stderr: ${stderrData.substring(0, 200)}`));
        }
      }
    });

    // 에러 처리
    sshProcess.on('error', (error) => {
      clearTimeout(timeoutId);
      if (!responseReceived) {
        responseReceived = true;
        reject(new Error(`SSH 연결 실패: ${error.message}`));
      }
    });

    // initialize 메시지 전송
    const initMessage = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {
          tools: {}
        },
        clientInfo: {
          name: "bom-tool-scanner",
          version: "1.0.0"
        }
      }
    };

    const toolsListMessage = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {}
    };

    try {
      sshProcess.stdin.write(JSON.stringify(initMessage) + '\n');
      setTimeout(() => {
        if (!responseReceived) {
          sshProcess.stdin.write(JSON.stringify(toolsListMessage) + '\n');
        }
      }, 500);
    } catch (error) {
      clearTimeout(timeoutId);
      if (!responseReceived) {
        responseReceived = true;
        reject(new Error(`메시지 전송 실패: ${error.message}`));
      }
    }
  });
}

/**
 * 등록 요청에서 Tool 목록 가져오기 (MCP Protocol 사용)
 * @param {Object} request - 등록 요청 정보
 * @param {string} request.github_link - GitHub 링크
 * @param {string} request.connection_snippet - 연결 정보 (JSON)
 * @returns {Promise<{tools: string[], method: string}>}
 */
async function scanToolsFromRequest(request) {
  // connection_snippet이 있으면 MCP Protocol 사용
  if (request.connection_snippet) {
    try {
      let connectionConfig;
      
      // JSON 파싱 시도
      try {
        connectionConfig = JSON.parse(request.connection_snippet);
      } catch (e) {
        // mcp.json 형식일 수 있음
        const mcpJsonMatch = request.connection_snippet.match(/\{[\s\S]*\}/);
        if (mcpJsonMatch) {
          connectionConfig = JSON.parse(mcpJsonMatch[0]);
        } else {
          throw new Error('연결 정보를 파싱할 수 없습니다.');
        }
      }

      // command 추출
      const command = connectionConfig.command;
      const args = connectionConfig.args || [];
      const env = connectionConfig.env || {};

      if (command) {
        try {
          const result = await getToolsFromMcpServer({ command, args, env });
          return {
            tools: result.tools,
            method: 'mcp_protocol'
          };
        } catch (error) {
          console.error('MCP Protocol 스캔 실패:', error.message);
          // Fallback: 코드 스캔으로
        }
      }
    } catch (error) {
      console.error('연결 정보 파싱 실패:', error.message);
    }
  }

  // Fallback: 코드 스캔
  if (request.github_link) {
    const { scanGitHubForTools } = require('./githubToolScanner');
    try {
      const result = await scanGitHubForTools(request.github_link);
      return {
        tools: result.tools,
        method: 'code_scan'
      };
    } catch (error) {
      console.error('코드 스캔 실패:', error.message);
    }
  }

  return {
    tools: [],
    method: 'none'
  };
}

module.exports = {
  getToolsFromMcpServer,
  getToolsFromSshServer,
  scanToolsFromRequest
};

