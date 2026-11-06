import { useEffect, useState } from "react";
import { Download } from "lucide-react";

export default function PWAInstallButton({ compact = false }) {
  const [installEvent, setInstallEvent] = useState(null);

  useEffect(() => {
    function handleBeforeInstallPrompt(event) {
      event.preventDefault();
      setInstallEvent(event);
    }

    function handleInstalled() {
      setInstallEvent(null);
    }

    window.addEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
    window.addEventListener("appinstalled", handleInstalled);

    return () => {
      window.removeEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
      window.removeEventListener("appinstalled", handleInstalled);
    };
  }, []);

  if (!installEvent) return null;

  async function installApp() {
    installEvent.prompt();
    await installEvent.userChoice;
    setInstallEvent(null);
  }

  return (
    <button
      className={compact ? "install-app-button compact" : "install-app-button"}
      type="button"
      onClick={installApp}
    >
      <Download size={16} />
      Install app
    </button>
  );
}