<?php
class Session
{
    function __construct()
    {
        session_set_save_handler(
            array(&$this, '_open'),
            array(&$this, '_close'),
            array(&$this, '_read'),
            array(&$this, '_write'),
            array(&$this, '_destroy'),
            array(&$this, '_gc'));
        register_shutdown_function('session_write_close');
    }

    public function Start()
    {
        session_start();
    }

    public function _open($save_path, $session_name)
    {
        $this->session_name = $session_name;
        return true;
    }

    public function _close()
    {
        return true;
    }

    public function _read($id)
    {
        return apc_fetch($this->session_name.$id);
    }

    public function _write($id, $sess_data)
    {
        return apc_store($this->session_name.$id, $sess_data, 60*60*24);
    }

    public function _destroy($id)
    {
        return apc_delete($this->session_name.$id);
    }

    public function _gc($maxlifetime)
    {
        return true;
    }
}
