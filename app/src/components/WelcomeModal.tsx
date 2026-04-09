import { useState, useEffect } from 'react';
import { Database, GitBranch, Shield } from 'lucide-react';

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { STORAGE_KEYS } from '@/lib/constants';

interface WelcomeModalProps {
  onClose?: () => void;
}

export function WelcomeModal({ onClose }: WelcomeModalProps) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const hasSeenWelcome = localStorage.getItem(STORAGE_KEYS.WELCOME_SHOWN) === 'true';
    if (!hasSeenWelcome) {
      setOpen(true);
    }
  }, []);

  const handleClose = () => {
    localStorage.setItem(STORAGE_KEYS.WELCOME_SHOWN, 'true');
    setOpen(false);
    onClose?.();
  };

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && handleClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl">欢迎使用 DataLineageAnalysis</DialogTitle>
          <DialogDescription>
            一个完全在浏览器中运行的隐私优先 SQL 血缘分析引擎。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="flex items-start gap-3">
            <Database className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <p className="font-medium text-sm">SQL 血缘分析</p>
              <p className="text-sm text-muted-foreground">
                可视化数据如何在表、CTE 和列之间流动。
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <GitBranch className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <p className="font-medium text-sm">多文件项目</p>
              <p className="text-sm text-muted-foreground">
                将您的 SQL 文件组织成项目，并分析文件之间的依赖关系。
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
            <div>
              <p className="font-medium text-sm">隐私优先</p>
              <p className="text-sm text-muted-foreground">
                所有分析都在您的浏览器本地运行。您的 SQL 永远不会离开您的机器。
              </p>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={handleClose}>开始使用</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
