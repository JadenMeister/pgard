<!-- corpus: expect=none -->
<template>
  <div>
    <p v-html="'<em>Beta</em>'"></p>
    <p>{{ message }}</p>
    <p v-text="message"></p>
  </div>
</template>
<script setup>
defineProps({ message: String });
</script>
