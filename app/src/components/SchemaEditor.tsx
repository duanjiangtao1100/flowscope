import { useState, useCallback } from 'react';
import { SqlView } from '@pondpilot/flowscope-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';
import { Button } from './ui/button';
import { useThemeStore, resolveTheme } from '@/lib/theme-store';
import type { Dialect } from '@/lib/project-store';

interface SchemaEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  schemaSQL: string;
  dialect: Dialect;
  onSave: (schemaSQL: string) => void;
  /** When true, schema is from backend and cannot be edited */
  isReadOnly?: boolean;
}

export function SchemaEditor({
  open,
  onOpenChange,
  schemaSQL,
  onSave,
  isReadOnly = false,
}: SchemaEditorProps) {
  const [editedSQL, setEditedSQL] = useState(schemaSQL);
  const theme = useThemeStore((state) => state.theme);
  const isDark = resolveTheme(theme) === 'dark';

  // Reset to prop value when dialog opens
  const handleOpenChange = useCallback(
    (newOpen: boolean) => {
      if (newOpen) {
        setEditedSQL(schemaSQL);
      }
      onOpenChange(newOpen);
    },
    [schemaSQL, onOpenChange]
  );

  const handleSave = useCallback(() => {
    if (isReadOnly) return;
    onSave(editedSQL);
    onOpenChange(false);
  }, [editedSQL, onSave, onOpenChange, isReadOnly]);

  const handleClose = useCallback(() => {
    setEditedSQL(schemaSQL); // Reset to original
    onOpenChange(false);
  }, [schemaSQL, onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>{isReadOnly ? '查看Schema' : '编辑Schema'}</DialogTitle>
          <DialogDescription>
            {isReadOnly
              ? '此schema已从服务器加载（数据库自省）。在serve模式下无法编辑。'
              : '使用CREATE TABLE语句定义您的数据库schema。此schema将用于增强血统分析，但不会显示在图表中。'}
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 min-h-0 border rounded-md overflow-hidden">
          <SqlView
            value={editedSQL}
            onChange={isReadOnly ? undefined : setEditedSQL}
            className="h-full"
            editable={!isReadOnly}
            isDark={isDark}
          />
        </div>

        <DialogFooter>
          {isReadOnly ? (
            <Button onClick={handleClose}>关闭</Button>
          ) : (
            <>
              <Button variant="outline" onClick={handleClose}>
                取消
              </Button>
              <Button onClick={handleSave}>保存Schema</Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
